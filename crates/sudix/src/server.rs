//! The broker daemon: socket loop, peer-credential auth, and the
//! policy → approval → execute → audit pipeline.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::approval::Approver;
use crate::audit;
use crate::policy::{Policy, Verdict};
use crate::protocol::{Request, Response};
use crate::scoping::{self, ApprovalState, Clock, RealClock, RuleScope};

/// Runtime configuration for the daemon.
pub struct Config {
    /// Where the listening unix socket lives.
    pub socket_path: PathBuf,
    /// UIDs permitted to submit requests. A connection from any other uid is
    /// refused before policy is even consulted.
    pub agent_uids: Vec<u32>,
    /// The authorization policy.
    pub policy: Policy,
    /// Per-rule scoping (cache TTL and rate limit); indexed parallel to allow rules.
    pub rule_scopes: Vec<RuleScope>,
    /// Append-only audit log path.
    pub audit_path: PathBuf,
}

/// Decide and (if approved) execute a request. This is the heart of the broker,
/// kept free of any socket concerns so it can be unit-tested with a fake
/// [`Approver`].
///
/// Pipeline, fail-closed at every step:
/// 1. policy check (deny-by-default) — denied requests never reach the human;
/// 2. human approval (out-of-band) — a non-affirmative answer denies;
/// 3. execution as the daemon's own (root) identity;
/// 4. audit, regardless of outcome.
pub fn handle_request(
    cfg: &Config,
    caller_uid: u32,
    approver: &dyn Approver,
    approval_state: &Mutex<ApprovalState>,
    clock: &dyn Clock,
    req: &Request,
) -> Response {
    if req.argv.is_empty() {
        audit_best_effort(cfg, caller_uid, req, "denied-empty");
        return Response::Denied {
            why: "empty argv".into(),
        };
    }

    let rule_index = match cfg.policy.evaluate(&req.argv) {
        Verdict::Denied { reason } => {
            audit_best_effort(cfg, caller_uid, req, "denied-policy");
            return Response::Denied { why: reason };
        }
        Verdict::Allowed { rule_index } => rule_index,
    };

    // Validate and canonicalize cwd before showing it to the human or using it
    // in exec — the client supplies this value and it must not be trusted raw.
    let Ok(cwd) = std::fs::canonicalize(&req.cwd) else {
        audit_best_effort(cfg, caller_uid, req, "denied-cwd");
        return Response::Denied {
            why: "invalid working directory".into(),
        };
    };
    if !cwd.is_dir() {
        audit_best_effort(cfg, caller_uid, req, "denied-cwd");
        return Response::Denied {
            why: "invalid working directory".into(),
        };
    }

    // Rate limiting: checked before prompting.
    if scoping::is_rate_limited(approval_state, &cfg.rule_scopes, rule_index, clock) {
        audit_best_effort(cfg, caller_uid, req, "denied-rate");
        return Response::Denied {
            why: "rate limit exceeded".into(),
        };
    }

    // Cache check: if a fresh approval exists, skip the human dialog.
    match scoping::check_cache(
        approval_state,
        &cfg.rule_scopes,
        rule_index,
        &req.argv,
        clock,
    ) {
        scoping::CacheVerdict::Hit => match execute(req, &cwd) {
            Ok((exit_code, stdout, stderr)) => {
                audit_best_effort(cfg, caller_uid, req, "approved-cached");
                return Response::Approved {
                    exit_code,
                    stdout,
                    stderr,
                };
            }
            Err(e) => {
                audit_best_effort(cfg, caller_uid, req, "execute-error");
                return Response::Denied {
                    why: format!("execution failed: {e}"),
                };
            }
        },
        scoping::CacheVerdict::Miss => {}
    }

    if !approver.approve(req) {
        audit_best_effort(cfg, caller_uid, req, "denied-user");
        return Response::Denied {
            why: "denied by user".into(),
        };
    }

    // Record the approval for cache and rate tracking.
    scoping::record_approval(
        approval_state,
        &cfg.rule_scopes,
        rule_index,
        &req.argv,
        clock,
    );

    match execute(req, &cwd) {
        Ok((exit_code, stdout, stderr)) => {
            audit_best_effort(cfg, caller_uid, req, "executed");
            Response::Approved {
                exit_code,
                stdout,
                stderr,
            }
        }
        Err(e) => {
            audit_best_effort(cfg, caller_uid, req, "execute-error");
            Response::Denied {
                why: format!("execution failed: {e}"),
            }
        }
    }
}

/// Run the approved command. The daemon runs as root, so the child inherits
/// root; we do not shell out — `argv` is passed directly to `execvp`, so there
/// is no shell-injection surface.
fn execute(req: &Request, cwd: &Path) -> io::Result<(i32, String, String)> {
    let output = Command::new(&req.argv[0])
        .args(&req.argv[1..])
        .current_dir(cwd)
        .output()?;
    let code = output.status.code().unwrap_or(-1);
    Ok((
        code,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

fn audit_best_effort(cfg: &Config, caller_uid: u32, req: &Request, outcome: &str) {
    if let Err(e) = audit::record(&cfg.audit_path, caller_uid, req, outcome) {
        eprintln!("sudixd: audit write failed: {e}");
    }
}

/// Bind the socket and serve connections forever. Each connection is one
/// request/response. Errors on a single connection are logged and skipped; they
/// never bring down the daemon.
///
/// # Errors
/// Returns an error only if the socket cannot be bound.
pub fn serve(cfg: &Config, approver: &dyn Approver) -> io::Result<()> {
    // Remove a stale socket from a previous run, then bind fresh.
    let _stale = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    restrict_socket_permissions(&cfg.socket_path)?;

    eprintln!(
        "sudixd: listening on {} (agent uids: {:?})",
        cfg.socket_path.display(),
        cfg.agent_uids
    );

    let state = Arc::new(Mutex::new(ApprovalState::new()));
    let clock = RealClock;

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_connection(cfg, approver, &state, &clock, &stream) {
                    eprintln!("sudixd: connection error: {e}");
                }
            }
            Err(e) => eprintln!("sudixd: accept error: {e}"),
        }
    }
    Ok(())
}

/// Lock the socket to owner-only access (0600). Defense in depth: the peer-cred
/// check is the real gate, but there is no reason for the socket to be group-
/// or world-reachable.
fn restrict_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn handle_connection(
    cfg: &Config,
    approver: &dyn Approver,
    state: &Mutex<ApprovalState>,
    clock: &dyn Clock,
    stream: &UnixStream,
) -> io::Result<()> {
    let caller_uid = peer_uid(stream)?;
    if !cfg.agent_uids.contains(&caller_uid) {
        // Refuse before reading anything from an unauthorized peer.
        let resp = Response::Denied {
            why: "caller uid not authorized".into(),
        };
        return write_response(stream, &resp);
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(()); // peer closed without sending a request
    }

    let resp = match Request::from_line(&line) {
        Ok(req) => handle_request(cfg, caller_uid, approver, state, clock, &req),
        Err(e) => Response::Denied {
            why: format!("malformed request: {e}"),
        },
    };
    write_response(stream, &resp)
}

/// Authenticate the connecting process by kernel-vouched credentials. The uid
/// here is supplied by the kernel via `SO_PEERCRED`, not by the peer, so it
/// cannot be spoofed.
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let cred = getsockopt(stream, PeerCredentials)
        .map_err(|e| io::Error::other(format!("getsockopt(SO_PEERCRED): {e}")))?;
    Ok(cred.uid())
}

fn write_response(mut stream: &UnixStream, resp: &Response) -> io::Result<()> {
    let line = resp
        .to_line()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Rule;
    use std::cell::Cell;

    use crate::scoping::{ApprovalState, RealClock};

    fn test_cfg(dir: &std::path::Path) -> Config {
        Config {
            socket_path: dir.join("sock"),
            agent_uids: vec![1000],
            policy: Policy::new(vec![Rule::new(["echo", "**"]).unwrap()], vec!["dd".into()]),
            rule_scopes: vec![],
            audit_path: dir.join("audit.log"),
        }
    }

    fn no_scoping() -> std::sync::Mutex<ApprovalState> {
        std::sync::Mutex::new(ApprovalState::new())
    }

    /// Approver that always answers a fixed verdict and counts calls, so we can
    /// assert it was (or was not) consulted.
    struct FakeApprover {
        answer: bool,
        calls: Cell<u32>,
    }
    impl Approver for FakeApprover {
        fn approve(&self, _req: &Request) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.answer
        }
    }

    fn req(parts: &[&str]) -> Request {
        Request {
            argv: parts.iter().map(|s| (*s).to_string()).collect(),
            cwd: ".".into(),
            reason: "test".into(),
        }
    }

    fn req_with_cwd(parts: &[&str], cwd: &str) -> Request {
        Request {
            argv: parts.iter().map(|s| (*s).to_string()).collect(),
            cwd: cwd.to_string(),
            reason: "test".into(),
        }
    }

    #[test]
    fn nonexistent_cwd_denied_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: true,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            &RealClock,
            &req_with_cwd(&["echo", "hi"], "/no/such/directory/ever"),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(approver.calls.get(), 0, "approver must not be consulted");
    }

    #[test]
    fn file_as_cwd_denied_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        // Create a regular file to use as "cwd".
        let file_path = dir.path().join("notadir");
        std::fs::write(&file_path, b"x").unwrap();
        let approver = FakeApprover {
            answer: true,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            &RealClock,
            &req_with_cwd(&["echo", "hi"], file_path.to_str().unwrap()),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(approver.calls.get(), 0, "approver must not be consulted");
    }

    #[test]
    fn policy_denial_skips_approval_and_execution() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: true,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            &RealClock,
            &req(&["rm", "-rf", "/"]),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        // The human must never be bothered for a command policy already refused.
        assert_eq!(approver.calls.get(), 0);
    }

    #[test]
    fn user_denial_blocks_execution() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: false,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            &RealClock,
            &req(&["echo", "hi"]),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(approver.calls.get(), 1);
    }

    #[test]
    fn approved_command_executes_and_returns_output() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: true,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            &RealClock,
            &req(&["echo", "hello"]),
        );
        match resp {
            Response::Approved {
                exit_code, stdout, ..
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim(), "hello");
            }
            Response::Denied { why } => panic!("expected approval, got denial: {why}"),
        }
    }

    #[test]
    fn every_outcome_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let yes = FakeApprover {
            answer: true,
            calls: Cell::new(0),
        };
        let state = no_scoping();
        handle_request(&cfg, 1000, &yes, &state, &RealClock, &req(&["echo", "ok"]));
        handle_request(&cfg, 1000, &yes, &state, &RealClock, &req(&["dd", "x"])); // policy-denied
        let body = std::fs::read_to_string(&cfg.audit_path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("executed"));
        assert!(body.contains("denied-policy"));
    }
}
