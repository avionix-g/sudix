//! Human-in-the-loop approval.
//!
//! Approval is the only boundary in the system that a misbehaving agent cannot
//! satisfy on its own: it is out-of-band (a desktop dialog, not the agent's
//! stdin) and it **fails closed** — any error, timeout, or non-affirmative
//! answer denies the request.
//!
//! The [`Approver`] trait exists so the server can be driven by a scripted
//! approver in tests; production uses [`AgentApprover`] or [`TotpApprover`].

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Secret, TOTP};

use crate::config::ApprovalMethod;
use crate::protocol::{Prompt, Request, Verdict};

/// The 3-state result of an approval attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Approval {
    Allowed,
    Denied,
    /// An internal failure prevented a decision. The human was not consulted.
    Error(String),
}

/// Something that can ask a human to approve a specific, already-policy-checked
/// request. Implementations MUST fail closed.
pub trait Approver: Send + Sync {
    /// Show the exact command and return the verdict.
    fn approve(&self, caller_uid: u32, req: &Request) -> Approval;
    /// Clone into a heap-allocated trait object (for `Arc::from`).
    fn clone_box(&self) -> Box<dyn Approver>;
}

/// Renders the message a human sees for a given prompt. Kept separate from the
/// dialog mechanism so it can be unit-tested without spawning anything.
#[must_use]
pub fn prompt_text(p: &Prompt) -> String {
    format!(
        "A coding agent is requesting root to run:\n\n\
         {}\n\n\
         Working directory: {}\n\
         Reason: {}\n\n\
         Allow this single command to run as root?",
        shell_join(&p.argv),
        p.cwd,
        p.reason,
    )
}

/// Spawn a zenity question dialog for the given prompt and return the verdict.
///
/// Uses `--no-markup` to prevent agent-controlled fields from injecting Pango
/// markup into the dialog text.
#[must_use]
pub fn spawn_zenity(p: &Prompt) -> Verdict {
    verdict_from_status(
        Command::new("zenity")
            .arg("--question")
            .arg("--no-markup")
            .arg("--title=sudix: root access requested")
            .arg(format!("--text={}", prompt_text(p)))
            .arg("--ok-label=Allow")
            .arg("--cancel-label=Deny")
            .arg("--default-cancel")
            .arg("--width=500")
            .status(),
    )
}

/// Map a zenity spawn result to a [`Verdict`]. Split from [`spawn_zenity`] so
/// the exit-status mapping can be unit-tested without spawning a real dialog.
///
/// zenity exits 0 for OK/Allow, non-zero for Cancel/Deny, window-close, and
/// timeout. A spawn failure (e.g. no display, zenity missing) is an error, not
/// a denial.
fn verdict_from_status(result: std::io::Result<std::process::ExitStatus>) -> Verdict {
    match result {
        Ok(s) if s.success() => Verdict::Allow,
        Ok(_) => Verdict::Deny,
        Err(e) => Verdict::Error {
            why: format!("zenity spawn failed: {e}"),
        },
    }
}

/// Join argv into a display string. This is for *human display only* — it is
/// never parsed back or fed to a shell, so simple quoting of whitespace-bearing
/// tokens is sufficient to keep the dialog unambiguous.
#[must_use]
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// TOTP approver
// ---------------------------------------------------------------------------

/// Headless approver: verifies a TOTP code supplied in the request.
///
/// The secret lives in a root-owned `0400` or `0600` file loaded once at startup.
/// A wrong code, a missing code, or a previously-used code all fail closed.
///
/// Each code is accepted at most once: the TOTP counter value (`unix_secs / step`)
/// is recorded in `used_counters` on first use and rejected on any subsequent
/// attempt within the same validity window. This prevents an agent from reusing a
/// human-supplied code to approve multiple distinct commands.
pub struct TotpApprover {
    totp: TOTP,
    /// Set of already-consumed TOTP counter values. Shared across all clones
    /// so replay is detected even if the approver is cloned for separate threads.
    used_counters: Arc<Mutex<HashSet<u64>>>,
}

impl TotpApprover {
    /// Load and construct from a secret file.
    ///
    /// The file must be root-owned and mode `0400` or `0600` (no group or world
    /// bits). A group- or world-readable secret file is refused.
    ///
    /// # Errors
    /// Returns a string describing the problem if the file cannot be read,
    /// has wrong permissions, or the secret cannot be decoded.
    pub fn from_secret_file(path: &Path) -> Result<Self, String> {
        Self::from_secret_file_inner(path, true)
    }

    fn from_secret_file_inner(path: &Path, enforce_perms: bool) -> Result<Self, String> {
        if enforce_perms {
            check_secret_permissions(path).map_err(|e| e.to_string())?;
        }
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let secret = Secret::Encoded(raw.trim().to_string())
            .to_bytes()
            .map_err(|e| format!("bad TOTP secret: {e:?}"))?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "sudix".to_string())
            .map_err(|e| format!("TOTP init error: {e:?}"))?;
        Ok(Self {
            totp,
            used_counters: Arc::new(Mutex::new(HashSet::new())),
        })
    }
}

impl Approver for TotpApprover {
    fn approve(&self, _caller_uid: u32, req: &Request) -> Approval {
        let Some(code) = req.otp.as_deref() else {
            return Approval::Denied;
        };
        if !self.totp.check_current(code).unwrap_or(false) {
            return Approval::Denied;
        }
        // Compute the counter value for the current time step.
        let step = self.totp.step;
        let counter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            / step;
        // Reject if this counter has already been consumed (replay prevention).
        let mut used = self
            .used_counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !used.insert(counter) {
            return Approval::Denied; // Code already used this time step.
        }
        Approval::Allowed
    }

    fn clone_box(&self) -> Box<dyn Approver> {
        Box::new(Self {
            totp: self.totp.clone(),
            used_counters: Arc::clone(&self.used_counters),
        })
    }
}

fn check_secret_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    // Reject any group or world access (read, write, or execute).
    // The secret must be 0400 or 0600 (owner-only read/write).
    if meta.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} has group or world permissions; refusing to use as TOTP secret (chmod 0600 or 0400)",
            path.display()
        )));
    }
    if meta.uid() != 0 {
        return Err(std::io::Error::other(format!(
            "{} is not owned by root; refusing to use as TOTP secret",
            path.display()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct the right [`Approver`] from config.
///
/// Returns `Ok(None)` for `ApprovalMethod::Agent` — the caller must build
/// an [`AgentApprover`] with the shared registry instead.
///
/// # Errors
/// Returns a string describing the problem if TOTP setup fails.
pub fn approver_for(
    method: &ApprovalMethod,
    totp_secret_path: Option<&str>,
    enforce_perms: bool,
) -> Result<Option<Box<dyn Approver + Send + Sync>>, String> {
    match method {
        ApprovalMethod::Agent => Ok(None),
        ApprovalMethod::Totp => {
            let path_str = totp_secret_path
                .ok_or_else(|| "TOTP method requires totp_secret_path".to_string())?;
            let path = Path::new(path_str);
            TotpApprover::from_secret_file_inner(path, enforce_perms)
                .map(|a| Some(Box::new(a) as Box<dyn Approver + Send + Sync>))
        }
    }
}

/// Timeout for a single prompt round-trip (user has this long to click).
const AGENT_PROMPT_TIMEOUT_SECS: u64 = 300;
/// Maximum bytes read from a verdict line. A verdict is tiny; capping prevents
/// a buggy/wedged agent from buffering unboundedly while holding the gate.
const MAX_VERDICT_BYTES: u64 = 4096;

/// A live connection to a registered per-user approval agent.
pub struct AgentHandle {
    stream: Mutex<UnixStream>,
    /// Signals when the agent has disconnected (prompt got EOF or error).
    disconnected: (Mutex<bool>, Condvar),
}

impl AgentHandle {
    #[must_use]
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
            disconnected: (Mutex::new(false), Condvar::new()),
        }
    }

    /// Block until the agent disconnects (prompt got EOF or error, or stream closed).
    pub fn wait_until_disconnected(&self) {
        let (ref lock, ref cv) = self.disconnected;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(
            cv.wait_while(guard, |d| !*d)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    fn signal_disconnected(&self) {
        let (ref lock, ref cv) = self.disconnected;
        let mut d = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *d = true;
        cv.notify_all();
    }

    /// Send a prompt and wait for a verdict. Serializes concurrent callers.
    pub fn prompt(&self, p: &Prompt) -> Approval {
        let mut guard = match self.stream.lock() {
            Ok(g) => g,
            Err(e) => return Approval::Error(format!("agent handle poisoned: {e}")),
        };
        let line = match p.to_line() {
            Ok(l) => l,
            Err(e) => return Approval::Error(format!("failed to serialize prompt: {e}")),
        };
        if let Err(e) = guard.write_all(line.as_bytes()) {
            self.signal_disconnected();
            return Approval::Error(format!("failed to send prompt to agent: {e}"));
        }
        if let Err(e) = guard.flush() {
            self.signal_disconnected();
            return Approval::Error(format!("failed to flush prompt to agent: {e}"));
        }
        if let Err(e) = guard.set_read_timeout(Some(Duration::from_secs(AGENT_PROMPT_TIMEOUT_SECS)))
        {
            return Approval::Error(format!("set_read_timeout failed: {e}"));
        }
        let mut reader = BufReader::new((&*guard).take(MAX_VERDICT_BYTES));
        let mut verdict_line = String::new();
        match reader.read_line(&mut verdict_line) {
            Err(e) => {
                self.signal_disconnected();
                return Approval::Error(format!("approval agent timed out or disconnected: {e}"));
            }
            Ok(0) => {
                self.signal_disconnected();
                return Approval::Error("approval agent disconnected".into());
            }
            Ok(_) => {}
        }
        match Verdict::from_line(&verdict_line) {
            Ok(Verdict::Allow) => Approval::Allowed,
            Ok(Verdict::Deny) => Approval::Denied,
            Ok(Verdict::Error { why }) => Approval::Error(why),
            Err(e) => Approval::Error(format!("malformed verdict from agent: {e}")),
        }
    }
}

/// Shared registry: maps uid → live agent connection.
pub type AgentRegistry = (Mutex<HashMap<u32, Arc<AgentHandle>>>, Condvar);

const NO_AGENT_MSG: &str = "no approval agent running in your session; is sudix-agent running?";

/// Approver that routes each prompt to the registered per-user agent.
pub struct AgentApprover {
    pub registry: Arc<AgentRegistry>,
    /// How long to wait for an agent to register before returning an error.
    pub register_wait: Duration,
    /// Serializes the dialog step: taken only after the registration wait so
    /// waiting for the agent does not block concurrent requests from other uids.
    pub approval_gate: Arc<Mutex<()>>,
}

impl Approver for AgentApprover {
    fn approve(&self, caller_uid: u32, req: &Request) -> Approval {
        let (ref lock, ref cv) = *self.registry;

        // Phase 1: wait for the agent to appear — no approval gate held.
        let deadline = std::time::Instant::now() + self.register_wait;
        let handle = loop {
            let guard = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(h) = guard.get(&caller_uid) {
                break Arc::clone(h);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Approval::Error(NO_AGENT_MSG.into());
            }
            let (_guard, timed_out) = cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if timed_out.timed_out() {
                return Approval::Error(NO_AGENT_MSG.into());
            }
        };

        let prompt = Prompt {
            argv: req.argv.clone(),
            cwd: req.cwd.clone(),
            reason: req.reason.clone(),
        };

        // Phase 2: gate the dialog itself so at most one dialog shows at a time.
        let _gate = self
            .approval_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handle.prompt(&prompt)
    }

    fn clone_box(&self) -> Box<dyn Approver> {
        Box::new(Self {
            registry: Arc::clone(&self.registry),
            register_wait: self.register_wait,
            approval_gate: Arc::clone(&self.approval_gate),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use totp_rs::{Algorithm, Secret, TOTP};

    fn req() -> Request {
        Request {
            argv: vec!["pacman".into(), "-S".into(), "ripgrep".into()],
            cwd: "/tmp".into(),
            reason: "demo".into(),
            otp: None,
        }
    }

    #[test]
    fn prompt_shows_the_exact_command() {
        let r = req();
        let p = Prompt {
            argv: r.argv.clone(),
            cwd: r.cwd.clone(),
            reason: r.reason.clone(),
        };
        let text = prompt_text(&p);
        assert!(text.contains("pacman -S ripgrep"));
        assert!(text.contains("Reason: demo"));
        assert!(text.contains("as root"));
    }

    #[test]
    fn shell_join_quotes_whitespace_args() {
        let joined = shell_join(&[
            "echo".to_string(),
            "hello world".to_string(),
            "plain".to_string(),
        ]);
        assert_eq!(joined, r#"echo "hello world" plain"#);
    }

    fn exit(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn zenity_exit_zero_maps_to_allow() {
        assert_eq!(verdict_from_status(Ok(exit(0))), Verdict::Allow);
    }

    #[test]
    fn zenity_exit_nonzero_maps_to_deny() {
        assert_eq!(verdict_from_status(Ok(exit(1))), Verdict::Deny);
    }

    #[test]
    fn zenity_spawn_failure_maps_to_error() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "zenity not found");
        assert!(matches!(
            verdict_from_status(Err(err)),
            Verdict::Error { .. }
        ));
    }

    fn make_totp(secret_bytes: &[u8]) -> TOTP {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.to_vec(),
            None,
            "sudix".to_string(),
        )
        .unwrap()
    }

    // A base32 secret ≥ 26 chars (≥ 16 decoded bytes) to satisfy totp-rs v5.
    const TEST_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX";

    #[test]
    fn totp_approver_accepts_current_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let totp = make_totp(&secret_bytes);
        let code = totp.generate_current().unwrap();

        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code),
        };
        assert_eq!(approver.approve(1000, &req), Approval::Allowed);
    }

    #[test]
    fn totp_approver_rejects_replay_of_used_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let totp = make_totp(&secret_bytes);
        let code = totp.generate_current().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code.clone()),
        };
        assert_eq!(
            approver.approve(1000, &req),
            Approval::Allowed,
            "first use must succeed"
        );
        let req2 = Request {
            argv: vec!["whoami".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code),
        };
        assert_eq!(
            approver.approve(1000, &req2),
            Approval::Denied,
            "replay must be rejected"
        );
    }

    #[test]
    fn totp_approver_rejects_wrong_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some("000000".into()),
        };
        assert_eq!(approver.approve(1000, &req), Approval::Denied);
    }

    #[test]
    fn totp_approver_rejects_missing_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        assert_eq!(approver.approve(1000, &req()), Approval::Denied); // otp = None
    }

    // --- AgentApprover tests ---

    fn make_registry() -> Arc<AgentRegistry> {
        Arc::new((Mutex::new(HashMap::new()), Condvar::new()))
    }

    fn agent_req() -> Request {
        Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: None,
        }
    }

    /// Spawn a fake agent thread that reads one Prompt and replies with the given Verdict.
    fn fake_agent(agent_stream: UnixStream, verdict: Verdict) {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(&agent_stream);
            let mut line = String::new();
            drop(reader.read_line(&mut line));
            let v_line = verdict.to_line().unwrap();
            let mut w = &agent_stream;
            drop(w.write_all(v_line.as_bytes()));
        });
    }

    #[test]
    fn agent_approver_allow() {
        let registry = make_registry();
        let (broker_side, agent_side) = UnixStream::pair().unwrap();
        fake_agent(agent_side, Verdict::Allow);
        {
            let (ref lock, ref cv) = *registry;
            lock.lock()
                .unwrap()
                .insert(1000, Arc::new(AgentHandle::new(broker_side)));
            cv.notify_all();
        }
        let approver = AgentApprover {
            registry,
            register_wait: Duration::from_millis(50),
            approval_gate: Arc::new(Mutex::new(())),
        };
        assert_eq!(approver.approve(1000, &agent_req()), Approval::Allowed);
    }

    #[test]
    fn agent_approver_deny() {
        let registry = make_registry();
        let (broker_side, agent_side) = UnixStream::pair().unwrap();
        fake_agent(agent_side, Verdict::Deny);
        {
            let (ref lock, ref cv) = *registry;
            lock.lock()
                .unwrap()
                .insert(1000, Arc::new(AgentHandle::new(broker_side)));
            cv.notify_all();
        }
        let approver = AgentApprover {
            registry,
            register_wait: Duration::from_millis(50),
            approval_gate: Arc::new(Mutex::new(())),
        };
        assert_eq!(approver.approve(1000, &agent_req()), Approval::Denied);
    }

    #[test]
    fn agent_approver_error_from_agent() {
        let registry = make_registry();
        let (broker_side, agent_side) = UnixStream::pair().unwrap();
        fake_agent(
            agent_side,
            Verdict::Error {
                why: "no display".into(),
            },
        );
        {
            let (ref lock, ref cv) = *registry;
            lock.lock()
                .unwrap()
                .insert(1000, Arc::new(AgentHandle::new(broker_side)));
            cv.notify_all();
        }
        let approver = AgentApprover {
            registry,
            register_wait: Duration::from_millis(50),
            approval_gate: Arc::new(Mutex::new(())),
        };
        assert!(matches!(
            approver.approve(1000, &agent_req()),
            Approval::Error(_)
        ));
    }

    #[test]
    fn agent_approver_no_agent_returns_error() {
        let registry = make_registry();
        let approver = AgentApprover {
            registry,
            register_wait: Duration::from_millis(50),
            approval_gate: Arc::new(Mutex::new(())),
        };
        let result = approver.approve(1000, &agent_req());
        assert!(matches!(result, Approval::Error(_)));
    }
}
