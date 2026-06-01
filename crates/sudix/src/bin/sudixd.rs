//! `sudixd` — the privileged broker daemon.
//!
//! Run as root (via systemd or `sudo sudixd`). Listens on a unix socket, gates
//! each request through policy + human approval, executes approved commands as
//! root, and audits everything.
//!
//! Configuration is intentionally hard-coded here for the sketch: the allowed
//! caller uid comes from `$SUDIX_ALLOWED_UID`, and the policy is the
//! [`default_policy`] below. A real deployment would load the policy from a
//! root-owned config file; keeping it in code for now means the allowlist is
//! reviewed in the same place as everything else.

use std::path::PathBuf;
use std::process::ExitCode;

use sudix::ZenityApprover;
use sudix::policy::{Policy, Rule};
use sudix::server::{Config, serve};

/// The starter allowlist. Deliberately tiny — read-mostly, low-blast-radius
/// commands. Edit and rebuild to extend; the hard denylist below can never be
/// overridden by an allow rule.
fn default_policy() -> Policy {
    let allow = [
        // Package management (Arch).
        vec!["pacman", "-S", "**"],
        vec!["pacman", "-Syu", "**"],
        // Service inspection/control.
        vec!["systemctl", "status", "*"],
        vec!["systemctl", "restart", "*"],
        // Trivially safe introspection, handy for smoke-testing.
        vec!["id"],
    ]
    .into_iter()
    .map(|toks| Rule::new(toks).expect("static rule is well-formed"))
    .collect();

    // Programs whose blast radius is unbounded regardless of args, or that
    // would let the agent escape the allowlist (a shell, an editor, etc.).
    let hard_deny = [
        "sh", "bash", "zsh", "fish", "dd", "mkfs", "fdisk", "parted", "tee", "chmod", "chown",
        "visudo", "su", "sudo", "env", "vi", "vim", "nano", "python", "perl",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    Policy::new(allow, hard_deny)
}

fn allowed_uid() -> Result<u32, String> {
    let raw = std::env::var("SUDIX_ALLOWED_UID")
        .map_err(|_| "set SUDIX_ALLOWED_UID to the uid permitted to call the broker".to_string())?;
    raw.parse::<u32>()
        .map_err(|e| format!("SUDIX_ALLOWED_UID is not a valid uid: {e}"))
}

fn main() -> ExitCode {
    let allowed_uid = match allowed_uid() {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("sudixd: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime_dir = std::env::var("SUDIX_RUNTIME_DIR").unwrap_or_else(|_| "/run/sudix".into());
    let cfg = Config {
        socket_path: PathBuf::from(&runtime_dir).join("sudixd.sock"),
        allowed_uid,
        policy: default_policy(),
        audit_path: PathBuf::from(&runtime_dir).join("audit.log"),
    };

    if let Some(parent) = cfg.socket_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("sudixd: cannot create {}: {e}", parent.display());
        return ExitCode::FAILURE;
    }

    match serve(&cfg, &ZenityApprover) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sudixd: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
