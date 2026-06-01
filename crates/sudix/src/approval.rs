//! Human-in-the-loop approval.
//!
//! Approval is the only boundary in the system that a misbehaving agent cannot
//! satisfy on its own: it is out-of-band (a desktop dialog, not the agent's
//! stdin) and it **fails closed** — any error, timeout, or non-affirmative
//! answer denies the request.
//!
//! The [`Approver`] trait exists so the server can be driven by a scripted
//! approver in tests; production uses [`ZenityApprover`].

use std::process::Command;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> Request {
        Request {
            argv: vec!["pacman".into(), "-S".into(), "ripgrep".into()],
            cwd: "/tmp".into(),
            reason: "demo".into(),
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
}
