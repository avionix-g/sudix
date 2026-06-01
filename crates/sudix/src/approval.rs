//! Human-in-the-loop approval.
//!
//! Approval is the only boundary in the system that a misbehaving agent cannot
//! satisfy on its own: it is out-of-band (a desktop dialog, not the agent's
//! stdin) and it **fails closed** — any error, timeout, or non-affirmative
//! answer denies the request.
//!
//! The [`Approver`] trait exists so the server can be driven by a scripted
//! approver in tests; production uses [`ZenityApprover`] or [`TotpApprover`].

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Secret, TOTP};

use crate::config::ApprovalMethod;
use crate::protocol::Request;

/// Something that can ask a human to approve a specific, already-policy-checked
/// request. Implementations MUST fail closed.
pub trait Approver: Send + Sync {
    /// Show the exact command and return `true` only on an explicit "Allow".
    fn approve(&self, req: &Request) -> bool;
    /// Clone into a heap-allocated trait object (for `Arc::from`).
    fn clone_box(&self) -> Box<dyn Approver>;
}

/// Renders the message a human sees. Kept separate from the dialog mechanism so
/// it can be unit-tested without spawning anything.
#[must_use]
pub fn prompt_text(req: &Request) -> String {
    format!(
        "A coding agent is requesting root to run:\n\n\
         {}\n\n\
         Working directory: {}\n\
         Reason: {}\n\n\
         Allow this single command to run as root?",
        shell_join(&req.argv),
        req.cwd,
        req.reason,
    )
}

/// Join argv into a display string. This is for *human display only* — it is
/// never parsed back or fed to a shell, so simple quoting of whitespace-bearing
/// tokens is sufficient to keep the dialog unambiguous.
fn shell_join(argv: &[String]) -> String {
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

/// Production approver: a `zenity --question` dialog.
#[derive(Debug, Default, Clone)]
pub struct ZenityApprover;

impl Approver for ZenityApprover {
    fn approve(&self, req: &Request) -> bool {
        // zenity exits 0 for the OK/Allow button, non-zero for Cancel/Deny,
        // window-close, and timeout. We additionally treat a spawn failure
        // (zenity missing, no display) as a denial — fail closed.
        //
        // --no-markup: suppress Pango markup interpretation so agent-controlled
        // reason/cwd fields cannot inject styled or misleading text.
        Command::new("zenity")
            .arg("--question")
            .arg("--no-markup")
            .arg("--title=sudix: root access requested")
            .arg(format!("--text={}", prompt_text(req)))
            .arg("--ok-label=Allow")
            .arg("--cancel-label=Deny")
            .arg("--default-cancel")
            .arg("--width=500")
            .status()
            .is_ok_and(|s| s.success())
    }

    fn clone_box(&self) -> Box<dyn Approver> {
        Box::new(Self)
    }
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
    fn approve(&self, req: &Request) -> bool {
        let Some(code) = req.otp.as_deref() else {
            return false; // No code provided → fail closed.
        };
        if !self.totp.check_current(code).unwrap_or(false) {
            return false;
        }
        // Compute the counter value for the current time step.
        let step = self.totp.step as u64;
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
            return false; // Code already used this time step.
        }
        true
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
/// # Errors
/// Returns a string describing the problem if TOTP setup fails.
pub fn approver_for(
    method: &ApprovalMethod,
    totp_secret_path: Option<&str>,
    enforce_perms: bool,
) -> Result<Box<dyn Approver + Send + Sync>, String> {
    match method {
        ApprovalMethod::Zenity => Ok(Box::new(ZenityApprover)),
        ApprovalMethod::Totp => {
            let path_str = totp_secret_path
                .ok_or_else(|| "TOTP method requires totp_secret_path".to_string())?;
            let path = Path::new(path_str);
            TotpApprover::from_secret_file_inner(path, enforce_perms)
                .map(|a| Box::new(a) as Box<dyn Approver + Send + Sync>)
        }
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
        let text = prompt_text(&req());
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
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code),
        };
        assert!(approver.approve(&req));
    }

    #[test]
    fn totp_approver_rejects_replay_of_used_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let totp = make_totp(&secret_bytes);
        let code = totp.generate_current().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code.clone()),
        };
        assert!(approver.approve(&req), "first use must succeed");
        let req2 = Request {
            argv: vec!["whoami".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some(code),
        };
        assert!(!approver.approve(&req2), "replay must be rejected");
    }

    #[test]
    fn totp_approver_rejects_wrong_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
            otp: Some("000000".into()),
        };
        assert!(!approver.approve(&req));
    }

    #[test]
    fn totp_approver_rejects_missing_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
            used_counters: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };
        assert!(!approver.approve(&req())); // otp = None
    }
}
