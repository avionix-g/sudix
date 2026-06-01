//! Human-in-the-loop approval.
//!
//! Approval is the only boundary in the system that a misbehaving agent cannot
//! satisfy on its own: it is out-of-band (a desktop dialog, not the agent's
//! stdin) and it **fails closed** — any error, timeout, or non-affirmative
//! answer denies the request.
//!
//! The [`Approver`] trait exists so the server can be driven by a scripted
//! approver in tests; production uses [`ZenityApprover`] or [`TotpApprover`].

use std::path::Path;
use std::process::Command;

use totp_rs::{Algorithm, Secret, TOTP};

use crate::config::ApprovalMethod;
use crate::protocol::Request;

/// Something that can ask a human to approve a specific, already-policy-checked
/// request. Implementations MUST fail closed.
pub trait Approver {
    /// Show the exact command and return `true` only on an explicit "Allow".
    fn approve(&self, req: &Request) -> bool;
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
        Command::new("zenity")
            .arg("--question")
            .arg("--title=sudix: root access requested")
            .arg(format!("--text={}", prompt_text(req)))
            .arg("--ok-label=Allow")
            .arg("--cancel-label=Deny")
            .arg("--default-cancel")
            .arg("--width=500")
            .status()
            .is_ok_and(|s| s.success())
    }
}

// ---------------------------------------------------------------------------
// TOTP approver
// ---------------------------------------------------------------------------

/// Headless approver: verifies a TOTP code supplied in the request.
///
/// The secret lives in a root-owned `0400` file loaded once at startup.
/// A wrong code, a missing code, and a spawn failure all fail closed.
///
/// **Replay note:** TOTP codes are valid for ~30–90 seconds depending on
/// clock skew. A used-code cache is out of scope for this plan; the
/// peer-cred + `0600` socket limit the exposure surface.
pub struct TotpApprover {
    totp: TOTP,
}

impl TotpApprover {
    /// Load and construct from a secret file.
    ///
    /// The file must be root-owned and mode `0400` (or at most `0600`). A
    /// group- or world-readable secret file is refused — the same permission
    /// model as the policy config.
    ///
    /// # Errors
    /// Returns a string describing the problem if the file cannot be read,
    /// has wrong permissions, or the secret cannot be decoded.
    pub fn from_secret_file(path: &Path) -> Result<Self, String> {
        check_secret_permissions(path).map_err(|e| e.to_string())?;
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let secret = Secret::Encoded(raw.trim().to_string())
            .to_bytes()
            .map_err(|e| format!("bad TOTP secret: {e:?}"))?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "sudix".to_string())
            .map_err(|e| format!("TOTP init error: {e:?}"))?;
        Ok(Self { totp })
    }
}

impl Approver for TotpApprover {
    fn approve(&self, req: &Request) -> bool {
        let Some(code) = req.otp.as_deref() else {
            return false; // No code provided → fail closed.
        };
        self.totp.check_current(code).unwrap_or(false)
    }
}

fn check_secret_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    if meta.mode() & 0o022 != 0 {
        return Err(std::io::Error::other(format!(
            "{} is group- or world-writable; refusing to use as TOTP secret",
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
            if enforce_perms {
                TotpApprover::from_secret_file(path)
                    .map(|a| Box::new(a) as Box<dyn Approver + Send + Sync>)
            } else {
                // Test path: load secret without perm enforcement.
                let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                let secret = Secret::Encoded(raw.trim().to_string())
                    .to_bytes()
                    .map_err(|e| format!("bad TOTP secret: {e:?}"))?;
                let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "sudix".to_string())
                    .map_err(|e| format!("TOTP init error: {e:?}"))?;
                Ok(Box::new(TotpApprover { totp }))
            }
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
    fn totp_approver_rejects_wrong_code() {
        let secret_bytes = Secret::Encoded(TEST_SECRET.to_string()).to_bytes().unwrap();
        let approver = TotpApprover {
            totp: make_totp(&secret_bytes),
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
        };
        assert!(!approver.approve(&req())); // otp = None
    }
}
