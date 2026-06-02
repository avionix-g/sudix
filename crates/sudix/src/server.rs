//! The broker daemon: socket loop, peer-credential auth, and the
//! policy → approval → execute → audit pipeline.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, RwLock};

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
use crate::config::{self, ConfigError, FileConfig};
use crate::policy::{Policy, Verdict};
use crate::protocol::{Hello, Request, Response};
use crate::scoping::{self, ApprovalState, Clock, RealClock, RuleScope};

/// The parts of the runtime config that a reload can change.
#[derive(Clone)]
pub struct PolicyBundle {
    pub policy: Policy,
    pub rule_scopes: Vec<RuleScope>,
    pub agent_uids: Vec<u32>,
}

/// Everything needed to reload: the file path + whether to enforce perms.
pub struct ReloadCtx {
    pub config_path: PathBuf,
    /// `false` only in tests (skips root-ownership check).
    pub enforce_perms: bool,
}

/// Runtime configuration for the daemon.
pub struct Config {
    /// Where the listening unix socket lives.
    pub socket_path: PathBuf,
    /// Append-only audit log path.
    pub audit_path: PathBuf,
    /// Reload parameters.
    pub reload: ReloadCtx,
    /// Current policy bundle; swapped on successful reload.
    pub current: RwLock<Arc<PolicyBundle>>,
    /// SHA-256 of the last-seen config file contents; `None` means "force a
    /// reload on next request".
    pub last_hash: Mutex<Option<[u8; 32]>>,
}

impl Config {
    /// Construct from a pre-built bundle. `initial_hash` should come from
    /// `config_hash(&config_path)` captured right after the initial load.
    #[must_use]
    pub fn new(
        socket_path: PathBuf,
        audit_path: PathBuf,
        reload: ReloadCtx,
        bundle: PolicyBundle,
        initial_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            socket_path,
            audit_path,
            reload,
            current: RwLock::new(Arc::new(bundle)),
            last_hash: Mutex::new(initial_hash),
        }
    }
}

/// Reload the policy bundle from disk if the file's contents changed since the
/// last successful load. On success, swaps in the new bundle and resets
/// approval state (rule indices may have shifted). On failure, leaves the
/// current bundle intact and returns the error so the caller can fail closed.
///
/// Lock ordering: `last_hash` is acquired before `current` and `state` to
/// prevent deadlock — all callers must follow this order.
fn maybe_reload(cfg: &Config, state: &Mutex<ApprovalState>) -> Result<(), ConfigError> {
    // Read hash outside the lock (cheap I/O, no need to serialize).
    let h = config::config_hash(&cfg.reload.config_path)?;

    // Hold last_hash across the load to single-flight concurrent reloads.
    // A second thread that blocked here will see *last == Some(h) and fast-path.
    let mut last = cfg
        .last_hash
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if *last == Some(h) {
        return Ok(()); // fast path: contents unchanged
    }

    match FileConfig::load_with_checks(&cfg.reload.config_path, cfg.reload.enforce_perms) {
        Ok(fc) => {
            let bundle = Arc::new(bundle_from_file_cfg(&fc));
            {
                let mut current = cfg
                    .current
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *current = bundle;
            }
            {
                let mut guard = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *guard = ApprovalState::new();
            }
            *last = Some(h);
            eprintln!(
                "sudixd: reloaded policy from {}",
                cfg.reload.config_path.display()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("sudixd: config reload failed, keeping previous policy: {e}");
            Err(e)
        }
    }
}

#[must_use]
pub fn bundle_from_file_cfg(fc: &FileConfig) -> PolicyBundle {
    let rule_scopes = fc
        .rule_scoping()
        .into_iter()
        .map(|(ttl, rate)| RuleScope {
            cache_ttl_secs: ttl,
            rate_per_min: rate,
        })
        .collect();
    PolicyBundle {
        policy: fc.build_policy(),
        rule_scopes,
        agent_uids: fc.agent_uids.clone(),
    }
}

/// Per-connection context snapshot passed to [`handle_request`].
pub struct RequestCtx<'a> {
    pub cfg: &'a Config,
    pub bundle: &'a PolicyBundle,
    pub caller_uid: u32,
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
    ctx: &RequestCtx<'_>,
    approver: &dyn Approver,
    approval_state: &Mutex<ApprovalState>,
    approval_mutex: Option<&Mutex<()>>,
    clock: &dyn Clock,
    req: &Request,
) -> Response {
    let RequestCtx {
        cfg,
        bundle,
        caller_uid,
    } = ctx;
    let caller_uid = *caller_uid;

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

    let rule_index = match bundle.policy.evaluate(&req.argv) {
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
    if scoping::is_rate_limited(approval_state, &bundle.rule_scopes, rule_index, clock) {
        audit_best_effort(cfg, caller_uid, req, Outcome::DeniedRate);
        return Response::Denied {
            why: "rate limit exceeded".into(),
        };
    }

    // Cache check: if a fresh approval exists, skip the human dialog.
    match scoping::check_cache(
        approval_state,
        &bundle.rule_scopes,
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
        &bundle.rule_scopes,
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

/// Bind the socket, set permissions, and log startup. Used by [`serve`] and
/// [`serve_with_registry`] to share the bind-and-log logic. The read-lock on
/// `cfg.current` is scoped to cloning `agent_uids` and dropped before any I/O.
///
/// # Errors
/// Returns an error if the socket cannot be bound or permissions cannot be set.
fn bind_and_log(cfg: &Arc<Config>) -> io::Result<UnixListener> {
    let agent_uids = {
        let b = cfg
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        b.agent_uids.clone()
    };
    let _stale = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    restrict_socket_permissions(&cfg.socket_path)?;
    eprintln!(
        "sudixd: listening on {} (agent uids: {:?})",
        cfg.socket_path.display(),
        agent_uids
    );
    Ok(listener)
}

/// Bind the socket and serve connections forever.
///
/// # Errors
/// Returns an error only if the socket cannot be bound.
pub fn serve(cfg: &Arc<Config>, approver: &dyn Approver) -> io::Result<()> {
    let listener = bind_and_log(cfg)?;
    serve_on(cfg, &listener, approver)
}

/// Bind the socket and serve connections forever, using the given registry.
///
/// Used when the caller must share the same registry with the [`AgentApprover`]
/// it passes in. For the TOTP/static path, use [`serve`] instead.
///
/// # Errors
/// Returns an error only if the socket cannot be bound.
pub fn serve_with_registry(
    cfg: &Arc<Config>,
    approver: &dyn Approver,
    registry: &Arc<AgentRegistry>,
) -> io::Result<()> {
    let listener = bind_and_log(cfg)?;
    serve_on_with_registry(cfg, &listener, approver, registry)
}

/// Serve connections on an already-bound listener, using the given registry.
///
/// # Errors
/// See [`serve_on`].
pub fn serve_on_with_registry(
    cfg: &Arc<Config>,
    listener: &UnixListener,
    base_approver: &dyn Approver,
    registry: &Arc<AgentRegistry>,
) -> io::Result<()> {
    // For the agent path, approval serialization is managed by AgentApprover's
    // own gate — no outer mutex is needed here.
    serve_on_with_registry_inner(Arc::clone(cfg), listener, base_approver, registry, None);
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn serve_on_with_registry_inner(
    cfg: Arc<Config>,
    listener: &UnixListener,
    base_approver: &dyn Approver,
    registry: &Arc<AgentRegistry>,
    outer_approval_gate: Option<&Arc<Mutex<()>>>,
) {
    let base_approver: Arc<dyn Approver> = Arc::from(base_approver.clone_box());
    let state = Arc::new(Mutex::new(ApprovalState::new()));
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
        let sem2 = Arc::clone(&sem);
        let registry2 = Arc::clone(registry);
        let gate2 = outer_approval_gate.map(Arc::clone);

        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Err(e) = handle_connection_threaded(
                    &cfg2,
                    &*base_approver2,
                    &state2,
                    gate2.as_deref(),
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
    cfg: &Arc<Config>,
    listener: &UnixListener,
    base_approver: &dyn Approver,
) -> io::Result<()> {
    let registry: Arc<AgentRegistry> = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
    // Serializes the blocking human-approval step so at most one dialog is
    // outstanding at a time. AgentApprover manages its own gate internally.
    let gate = Arc::new(Mutex::new(()));
    serve_on_with_registry_inner(
        Arc::clone(cfg),
        listener,
        base_approver,
        &registry,
        Some(&gate),
    );
    Ok(())
}

/// Set the socket mode to 0666. Authorization is by peer-cred (`SO_PEERCRED`),
/// not by filesystem permission — the mode only controls who may *attempt* a
/// connection, and non-root callers (including sudix-agent) need to reach it.
/// 0666 here matches the systemd SocketMode=0666 so both code paths agree.
fn restrict_socket_permissions(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
}

fn handle_connection_threaded(
    cfg: &Config,
    base_approver: &dyn Approver,
    state: &Mutex<ApprovalState>,
    approval_mutex: Option<&Mutex<()>>,
    registry: &Arc<AgentRegistry>,
    stream: &UnixStream,
) -> io::Result<()> {
    // Reload policy before auth so a reload can update agent_uids too.
    if let Err(e) = maybe_reload(cfg, state) {
        let resp = Response::Error {
            why: format!("config reload failed; request refused: {e}"),
        };
        return write_response(stream, &resp);
    }

    // Snapshot the current bundle for this connection.
    let bundle: Arc<PolicyBundle> = {
        cfg.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };

    let caller_uid = peer_uid(stream)?;
    if !bundle.agent_uids.contains(&caller_uid) {
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
                &RequestCtx {
                    cfg,
                    bundle: &bundle,
                    caller_uid,
                },
                base_approver,
                state,
                approval_mutex,
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
    use crate::config::FileConfig;
    use crate::scoping::{ApprovalState, RealClock};
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Build a minimal `FileConfig` TOML, write to a tempfile, and load it.
    fn write_config(dir: &std::path::Path, toml: &str) -> std::path::PathBuf {
        let path = dir.join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        path
    }

    fn test_cfg(dir: &std::path::Path) -> Arc<Config> {
        let config_path = write_config(
            dir,
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] } ]
deny  = [ { argv = ["dd", { rest = true }] } ]
"#,
        );
        let fc = FileConfig::load_with_checks(&config_path, false).unwrap();
        let initial_hash = config::config_hash(&config_path).ok();
        let bundle = bundle_from_file_cfg(&fc);
        Arc::new(Config::new(
            dir.join("sock"),
            dir.join("audit.log"),
            ReloadCtx {
                config_path,
                enforce_perms: false,
            },
            bundle,
            initial_hash,
        ))
    }

    fn no_scoping() -> std::sync::Mutex<ApprovalState> {
        std::sync::Mutex::new(ApprovalState::new())
    }

    /// Approver that always answers a fixed verdict and counts calls.
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

    fn bundle(cfg: &Config) -> Arc<PolicyBundle> {
        cfg.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
        let file_path = dir.path().join("notadir");
        std::fs::write(&file_path, b"x").unwrap();
        let approver = FakeApprover {
            answer: Approval::Allowed,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let state = no_scoping();
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
            &approver,
            &state,
            None,
            &RealClock,
            &req(&["rm", "-rf", "/"]),
        );
        assert!(matches!(resp, Response::Denied { .. }));
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
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
        let b = bundle(&cfg);
        handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
            &yes,
            &state,
            None,
            &RealClock,
            &req(&["echo", "ok"]),
        );
        handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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
            approval_gate: Arc::new(Mutex::new(())),
        };
        let state = no_scoping();
        let b = bundle(&cfg);
        let resp = handle_request(
            &RequestCtx {
                cfg: &cfg,
                bundle: &b,
                caller_uid: 1000,
            },
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

    // --- hot-reload tests ---

    #[test]
    fn reload_picks_up_new_allow_rule() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] } ]
"#,
        );
        let fc = FileConfig::load_with_checks(&config_path, false).unwrap();
        let initial_hash = config::config_hash(&config_path).ok();
        let bundle_init = bundle_from_file_cfg(&fc);
        let cfg = Arc::new(Config::new(
            dir.path().join("sock"),
            dir.path().join("audit.log"),
            ReloadCtx {
                config_path: config_path.clone(),
                enforce_perms: false,
            },
            bundle_init,
            initial_hash,
        ));
        let state = Arc::new(Mutex::new(ApprovalState::new()));

        // id is not allowed yet.
        assert!(
            !bundle(&cfg)
                .policy
                .evaluate(&["id"].map(str::to_string))
                .is_allowed()
        );

        // Rewrite config to also allow `id`, force reload by clearing last_hash.
        std::fs::write(
            &config_path,
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] }, { argv = ["id"] } ]
"#,
        )
        .unwrap();
        {
            let mut last = cfg
                .last_hash
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *last = None;
        }

        maybe_reload(&cfg, &state).unwrap();
        assert!(
            bundle(&cfg)
                .policy
                .evaluate(&["id"].map(str::to_string))
                .is_allowed()
        );
    }

    #[test]
    fn reload_failure_fails_closed_and_keeps_old_policy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] } ]
"#,
        );
        let fc = FileConfig::load_with_checks(&config_path, false).unwrap();
        let initial_hash = config::config_hash(&config_path).ok();
        let bundle_init = bundle_from_file_cfg(&fc);
        let cfg = Arc::new(Config::new(
            dir.path().join("sock"),
            dir.path().join("audit.log"),
            ReloadCtx {
                config_path: config_path.clone(),
                enforce_perms: false,
            },
            bundle_init,
            initial_hash,
        ));
        let state = Arc::new(Mutex::new(ApprovalState::new()));

        // Break the config and force a reload.
        std::fs::write(&config_path, b"this is not valid toml ???").unwrap();
        {
            let mut last = cfg
                .last_hash
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *last = None;
        }

        assert!(maybe_reload(&cfg, &state).is_err());
        // Old policy still intact: echo still allowed.
        assert!(
            bundle(&cfg)
                .policy
                .evaluate(&["echo", "hi"].map(str::to_string))
                .is_allowed()
        );
    }

    #[test]
    fn same_content_skips_reload() {
        let dir = tempfile::tempdir().unwrap();
        let config_a = r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] } ]
"#;
        let config_path = write_config(dir.path(), config_a);
        let fc = FileConfig::load_with_checks(&config_path, false).unwrap();
        let initial_hash = config::config_hash(&config_path).ok();
        let bundle_init = bundle_from_file_cfg(&fc);
        let cfg = Arc::new(Config::new(
            dir.path().join("sock"),
            dir.path().join("audit.log"),
            ReloadCtx {
                config_path: config_path.clone(),
                enforce_perms: false,
            },
            bundle_init,
            initial_hash,
        ));
        let state = Arc::new(Mutex::new(ApprovalState::new()));

        // Seed last_hash = current file hash; id not in config A.
        let current_hash = config::config_hash(&config_path).ok();
        {
            let mut last = cfg
                .last_hash
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *last = current_hash;
        }

        // Fast path: hash matches, no reload even though content is present on disk.
        maybe_reload(&cfg, &state).unwrap();
        assert!(
            !bundle(&cfg)
                .policy
                .evaluate(&["id"].map(str::to_string))
                .is_allowed(),
            "id must not be allowed — config A has no id rule"
        );

        // Now change the file to config B (adds id). Hash differs → reload fires.
        std::fs::write(
            &config_path,
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }] }, { argv = ["id"] } ]
"#,
        )
        .unwrap();
        maybe_reload(&cfg, &state).unwrap();
        assert!(
            bundle(&cfg)
                .policy
                .evaluate(&["id"].map(str::to_string))
                .is_allowed(),
            "id must be allowed after reload with config B"
        );
    }

    #[test]
    fn approval_state_cleared_on_rule_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = ["echo", { rest = true }], cache_ttl_secs = 300 } ]
"#,
        );
        let fc = FileConfig::load_with_checks(&config_path, false).unwrap();
        let initial_hash = config::config_hash(&config_path).ok();
        let bundle_init = bundle_from_file_cfg(&fc);
        let cfg = Arc::new(Config::new(
            dir.path().join("sock"),
            dir.path().join("audit.log"),
            ReloadCtx {
                config_path: config_path.clone(),
                enforce_perms: false,
            },
            bundle_init,
            initial_hash,
        ));
        let state = Arc::new(Mutex::new(ApprovalState::new()));
        let clock = RealClock;

        // Prime a cache entry.
        scoping::record_approval(
            &state,
            &bundle(&cfg).rule_scopes,
            0,
            &["echo", "hi"].map(str::to_string),
            &clock,
        );
        assert!(matches!(
            scoping::check_cache(
                &state,
                &bundle(&cfg).rule_scopes,
                0,
                &["echo", "hi"].map(str::to_string),
                &clock,
            ),
            scoping::CacheVerdict::Hit
        ));

        // Force a reload by clearing last_hash (same config content is fine).
        {
            let mut last = cfg
                .last_hash
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *last = None;
        }
        maybe_reload(&cfg, &state).unwrap();

        // Cache must be cleared.
        assert!(matches!(
            scoping::check_cache(
                &state,
                &bundle(&cfg).rule_scopes,
                0,
                &["echo", "hi"].map(str::to_string),
                &clock,
            ),
            scoping::CacheVerdict::Miss
        ));
    }
}
