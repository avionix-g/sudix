//! The broker daemon: socket loop, peer-credential auth, and the
//! policy → approval → execute → audit pipeline.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};

/// Maximum concurrent connections. Over this, new connections block until a
/// slot is free. Guards against resource exhaustion at the daemon's expected
/// low-volume use.
const MAX_CONCURRENT: usize = 16;
/// Maximum bytes read from the request socket before treating the line as
/// malformed. argv + cwd + reason + OTP is never close to 64 KiB.
const MAX_REQUEST_BYTES: u64 = 65_536;
/// Maximum bytes for the agent-supplied reason field.
const MAX_REASON_BYTES: usize = 512;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::approval::{AgentHandle, AgentRegistry, Approval, Approver};
use crate::audit::{self, Outcome};
use crate::policy::{Policy, Verdict};
use crate::protocol::{Hello, Request, Response};
use crate::scoping::{self, ApprovalState, Clock, RealClock, RuleScope};

/// Runtime configuration for the daemon.
#[derive(Clone)]
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
/// `approval_mutex` serializes the blocking human-approval step so at most one
/// dialog is outstanding at a time. Pass `None` only in tests (a fresh
/// `Mutex::new(())` inside the call is equivalent and cheap).
///
/// Pipeline, fail-closed at every step:
/// 1. policy check (deny-by-default) — denied requests never reach the human;
/// 2. human approval (out-of-band) — a non-affirmative answer denies;
/// 3. execution as the daemon's own (root) identity;
/// 4. audit, regardless of outcome.
#[allow(clippy::too_many_lines)]
pub fn handle_request(
    cfg: &Config,
    caller_uid: u32,
    approver: &dyn Approver,
    approval_state: &Mutex<ApprovalState>,
    approval_mutex: Option<&Mutex<()>>,
    clock: &dyn Clock,
    req: &Request,
) -> Response {
    if req.argv.is_empty() {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedEmpty);
        return Response::Denied {
            why: "empty argv".into(),
        };
    }

    // Bound agent-controlled free-text fields to prevent dialog abuse.
    if req.reason.len() > MAX_REASON_BYTES {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedReason);
        return Response::Denied {
            why: "reason field too long".into(),
        };
    }

    let rule_index = match cfg.policy.evaluate(&req.argv) {
        Verdict::Denied { reason } => {
            audit_best_effort(cfg, caller_uid, req, Outcome::DeniedPolicy);
            return Response::Denied { why: reason };
        }
        Verdict::Allowed { rule_index } => rule_index,
    };

    // Validate and canonicalize cwd before showing it to the human or using it
    // in exec — the client supplies this value and it must not be trusted raw.
    let Ok(cwd) = std::fs::canonicalize(&req.cwd) else {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedCwd);
        return Response::Denied {
            why: "invalid working directory".into(),
        };
    };
    if !cwd.is_dir() {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedCwd);
        return Response::Denied {
            why: "invalid working directory".into(),
        };
    }

    // Rate limiting: checked before prompting.
    if scoping::is_rate_limited(approval_state, &cfg.rule_scopes, rule_index, clock) {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedRate);
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
        scoping::CacheVerdict::Hit => {
            // Record the cached execution in the rate window too.
            scoping::record_cache_hit(approval_state, rule_index, clock);
            match execute(req, &cwd) {
                Ok((exit_code, stdout, stderr)) => {
                    audit_best_effort(cfg, caller_uid, req, Outcome::ApprovedCached { exit_code });
                    return Response::Approved {
                        exit_code,
                        stdout,
                        stderr,
                    };
                }
                Err(e) => {
                    audit_best_effort(cfg, caller_uid, req, Outcome::ExecuteError);
                    return Response::Denied {
                        why: format!("execution failed: {e}"),
                    };
                }
            }
        }
        scoping::CacheVerdict::Miss => {}
    }

    // Serialize the human-facing approval step. Cache misses reach here.
    // The lock is held only across the blocking approver call; never across I/O
    // or state-mutex operations (lock-ordering: approval_mutex, then state_mutex
    // separately — never hold both at once).
    let local_mutex;
    let gate: &Mutex<()> = if let Some(m) = approval_mutex {
        m
    } else {
        local_mutex = Mutex::new(());
        &local_mutex
    };
    let approval = {
        let _guard = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        approver.approve(caller_uid, req)
    };

    match approval {
        Approval::Denied => {
            audit_best_effort(cfg, caller_uid, req, Outcome::DeniedUser);
            return Response::Denied {
                why: "denied by user".into(),
            };
        }
        Approval::Error(why) => {
            audit_best_effort(cfg, caller_uid, req, Outcome::ApproverError);
            return Response::Error { why };
        }
        Approval::Allowed => {}
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
            audit_best_effort(cfg, caller_uid, req, Outcome::Executed { exit_code });
            Response::Approved {
                exit_code,
                stdout,
                stderr,
            }
        }
        Err(e) => {
            audit_best_effort(cfg, caller_uid, req, Outcome::ExecuteError);
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

fn audit_best_effort(cfg: &Config, caller_uid: u32, req: &Request, outcome: Outcome) {
    if let Err(e) = audit::record(&cfg.audit_path, caller_uid, req, outcome) {
        eprintln!("sudixd: audit write failed: {e}");
    }
}

/// Bind the socket and serve connections forever.
///
/// # Errors
/// Returns an error only if the socket cannot be bound.
pub fn serve(cfg: &Config, approver: &dyn Approver) -> io::Result<()> {
    let _stale = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    restrict_socket_permissions(&cfg.socket_path)?;
    eprintln!(
        "sudixd: listening on {} (agent uids: {:?})",
        cfg.socket_path.display(),
        cfg.agent_uids
    );
    serve_on(&listener, cfg, approver)
}

/// Bind the socket and serve connections forever, using the given registry.
///
/// Used when the caller must share the same registry with the [`AgentApprover`]
/// it passes in. For the TOTP/static path, use [`serve`] instead.
///
/// # Errors
/// Returns an error only if the socket cannot be bound.
pub fn serve_with_registry(
    cfg: &Config,
    approver: &dyn Approver,
    registry: &Arc<AgentRegistry>,
) -> io::Result<()> {
    let _stale = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    restrict_socket_permissions(&cfg.socket_path)?;
    eprintln!(
        "sudixd: listening on {} (agent uids: {:?})",
        cfg.socket_path.display(),
        cfg.agent_uids
    );
    serve_on_with_registry(&listener, cfg, approver, registry)
}

/// Serve connections on an already-bound listener, using the given registry.
///
/// # Errors
/// See [`serve_on`].
pub fn serve_on_with_registry(
    listener: &UnixListener,
    cfg: &Config,
    base_approver: &dyn Approver,
    registry: &Arc<AgentRegistry>,
) -> io::Result<()> {
    let cfg = Arc::new(cfg.clone());
    let base_approver: Arc<dyn Approver> = Arc::from(base_approver.clone_box());
    let state = Arc::new(Mutex::new(ApprovalState::new()));
    // Serializes the blocking human-approval step so only one dialog shows at a time.
    let approval_mutex: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    // Counting semaphore: limits concurrent threads to MAX_CONCURRENT.
    let sem: Arc<(Mutex<usize>, Condvar)> = Arc::new((Mutex::new(0usize), Condvar::new()));

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sudixd: accept error: {e}");
                continue;
            }
        };

        // Wait for a slot.
        {
            let (lock, cvar) = sem.as_ref();
            let mut count = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            count = cvar
                .wait_while(count, |c| *c >= MAX_CONCURRENT)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *count += 1;
        }

        let cfg2 = Arc::clone(&cfg);
        let base_approver2 = Arc::clone(&base_approver);
        let state2 = Arc::clone(&state);
        let amtx2 = Arc::clone(&approval_mutex);
        let sem2 = Arc::clone(&sem);
        let registry2 = Arc::clone(registry);

        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Err(e) = handle_connection_threaded(
                    &cfg2,
                    &*base_approver2,
                    &state2,
                    &amtx2,
                    &registry2,
                    &stream,
                ) {
                    eprintln!("sudixd: connection error: {e}");
                }
            }));
            if result.is_err() {
                eprintln!("sudixd: worker thread panicked; connection dropped");
            }
            // Release slot.
            let (lock, cvar) = sem2.as_ref();
            let mut count = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *count -= 1;
            cvar.notify_one();
        });
    }
    Ok(())
}

/// Serve connections on an already-bound listener.
///
/// # Errors
/// See [`serve`].
///
/// Splits socket binding from serving so integration tests can inject their own
/// listener, and so systemd socket activation can hand over a pre-bound fd.
///
/// Each connection gets its own thread. The human-facing approval step is
/// serialized via a dedicated mutex so at most one dialog is outstanding at a
/// time. Cache/rate state updates take a separate short-lived lock.
///
/// Lock ordering (never hold both simultaneously):
///   `approval_mutex` first, then `state_mutex` in a separate lock scope.
///
/// # Errors
/// Returns an error only if `listener.incoming()` itself fails unrecoverably
/// (in practice this means the listener was already closed).
pub fn serve_on(
    listener: &UnixListener,
    cfg: &Config,
    base_approver: &dyn Approver,
) -> io::Result<()> {
    let registry: Arc<AgentRegistry> = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
    serve_on_with_registry(listener, cfg, base_approver, &registry)
}

/// Lock the socket to owner-only access (0600). Defense in depth: the peer-cred
/// check is the real gate, but there is no reason for the socket to be group-
/// or world-reachable.
fn restrict_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn handle_connection_threaded(
    cfg: &Config,
    base_approver: &dyn Approver,
    state: &Mutex<ApprovalState>,
    approval_mutex: &Mutex<()>,
    registry: &Arc<AgentRegistry>,
    stream: &UnixStream,
) -> io::Result<()> {
    let caller_uid = peer_uid(stream)?;
    if !cfg.agent_uids.contains(&caller_uid) {
        let resp = Response::Denied {
            why: "caller uid not authorized".into(),
        };
        return write_response(stream, &resp);
    }

    let reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.take(MAX_REQUEST_BYTES).read_line(&mut line)? == 0 {
        return Ok(());
    }
    // A full read that consumed every byte of the cap without a newline means
    // the line was truncated — treat as malformed rather than buffer more.
    if line.len() as u64 >= MAX_REQUEST_BYTES && !line.ends_with('\n') {
        let resp = Response::Denied {
            why: "request too large".into(),
        };
        return write_response(stream, &resp);
    }

    let clock = RealClock;
    match Hello::from_line(&line) {
        Ok(Hello::Command(req)) => {
            let resp = handle_request(
                cfg,
                caller_uid,
                base_approver,
                state,
                Some(approval_mutex),
                &clock,
                &req,
            );
            write_response(stream, &resp)
        }
        Ok(Hello::RegisterAgent) => {
            // Insert this connection as the live agent for caller_uid.
            let handle = Arc::new(AgentHandle::new(stream.try_clone()?));
            {
                let (ref lock, ref cv) = **registry;
                let mut reg = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                reg.insert(caller_uid, Arc::clone(&handle));
                cv.notify_all();
            }

            // Block until the agent disconnects; AgentHandle::prompt signals
            // disconnection when it gets EOF or an I/O error.
            handle.wait_until_disconnected();

            // Remove from registry on disconnect.
            let (ref lock, _) = **registry;
            let mut reg = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.remove(&caller_uid);
            Ok(())
        }
        Err(e) => {
            let resp = Response::Denied {
                why: format!("malformed request: {e}"),
            };
            write_response(stream, &resp)
        }
    }
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

    use crate::scoping::{ApprovalState, RealClock};
    use std::sync::atomic::{AtomicU32, Ordering};

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
        answer: Approval,
        calls: Arc<AtomicU32>,
    }
    impl Approver for FakeApprover {
        fn approve(&self, _caller_uid: u32, _req: &Request) -> Approval {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match &self.answer {
                Approval::Allowed => Approval::Allowed,
                Approval::Denied => Approval::Denied,
                Approval::Error(e) => Approval::Error(e.clone()),
            }
        }

        fn clone_box(&self) -> Box<dyn Approver> {
            Box::new(Self {
                answer: match &self.answer {
                    Approval::Allowed => Approval::Allowed,
                    Approval::Denied => Approval::Denied,
                    Approval::Error(e) => Approval::Error(e.clone()),
                },
                calls: Arc::clone(&self.calls),
            })
        }
    }

    fn req(parts: &[&str]) -> Request {
        Request {
            argv: parts.iter().map(|s| (*s).to_string()).collect(),
            cwd: ".".into(),
            reason: "test".into(),
            otp: None,
        }
    }

    fn req_with_cwd(parts: &[&str], cwd: &str) -> Request {
        Request {
            argv: parts.iter().map(|s| (*s).to_string()).collect(),
            cwd: cwd.to_string(),
            reason: "test".into(),
            otp: None,
        }
    }

    #[test]
    fn nonexistent_cwd_denied_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req_with_cwd(&["echo", "hi"], "/no/such/directory/ever"),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(
            approver.calls.load(Ordering::Relaxed),
            0,
            "approver must not be consulted"
        );
    }

    #[test]
    fn file_as_cwd_denied_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        // Create a regular file to use as "cwd".
        let file_path = dir.path().join("notadir");
        std::fs::write(&file_path, b"x").unwrap();
        let approver = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req_with_cwd(&["echo", "hi"], file_path.to_str().unwrap()),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(
            approver.calls.load(Ordering::Relaxed),
            0,
            "approver must not be consulted"
        );
    }

    #[test]
    fn policy_denial_skips_approval_and_execution() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req(&["rm", "-rf", "/"]),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        // The human must never be bothered for a command policy already refused.
        assert_eq!(approver.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn user_denial_blocks_execution() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: Approval::Denied,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req(&["echo", "hi"]),
        );
        assert!(matches!(resp, Response::Denied { .. }));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn approver_error_yields_response_error_and_audits_approver_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: Approval::Error("no agent running".into()),
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req(&["echo", "hi"]),
        );
        assert!(matches!(resp, Response::Error { .. }));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 1);
        let body = std::fs::read_to_string(&cfg.audit_path).unwrap();
        assert!(body.contains("approver-error"));
    }

    #[test]
    fn approved_command_executes_and_returns_output() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let approver = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
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
            Response::Error { why } => panic!("expected approval, got error: {why}"),
        }
    }

    #[test]
    fn every_outcome_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let yes = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        handle_request(
            &cfg,
            1000,
            &yes,
            &state,
            None,
            &RealClock,
            &req(&["echo", "ok"]),
        );
        handle_request(
            &cfg,
            1000,
            &yes,
            &state,
            None,
            &RealClock,
            &req(&["dd", "x"]),
        ); // policy-denied
        let body = std::fs::read_to_string(&cfg.audit_path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("executed"));
        assert!(body.contains("denied-policy"));
    }

    #[test]
    fn agent_approver_no_agent_yields_response_error() {
        use crate::approval::{AgentApprover, AgentRegistry};
        use std::collections::HashMap;
        use std::sync::Condvar;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        let registry: Arc<AgentRegistry> = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
        let approver = AgentApprover {
            registry,
            register_wait: Duration::from_millis(50),
        };
        let state = no_scoping();
        let resp = handle_request(
            &cfg,
            1000,
            &approver,
            &state,
            None,
            &RealClock,
            &req(&["echo", "hi"]),
        );
        assert!(
            matches!(resp, Response::Error { .. }),
            "expected Error, got {resp:?}"
        );
    }
}
