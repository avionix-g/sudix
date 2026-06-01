//! `sudixd` — the privileged broker daemon.
//!
//! Run as root (via systemd or `sudo sudixd`). Listens on a unix socket, gates
//! each request through policy + human approval, executes approved commands as
//! root, and audits everything.
//!
//! Configuration is loaded from a root-owned TOML file (default
//! `/etc/sudix/policy.toml`, override with `$SUDIX_CONFIG`). The daemon
//! **refuses to start** if the config is missing, unparseable, or invalid.
//!
//! Subcommands:
//!   `sudixd default-config`  — print a starter config to stdout and exit 0.

use std::path::PathBuf;
use std::process::ExitCode;

use sudix::ZenityApprover;
use sudix::config::{self, FileConfig};
use sudix::server::{Config, serve};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    if let Some(subcmd) = args.next() {
        match subcmd.as_str() {
            "default-config" => {
                print!("{}", config::default_config_toml());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("sudixd: unknown subcommand: {other}");
                eprintln!("usage: sudixd [default-config]");
                return ExitCode::FAILURE;
            }
        }
    }

    let config_path =
        std::env::var("SUDIX_CONFIG").unwrap_or_else(|_| config::DEFAULT_CONFIG_PATH.to_string());

    let file_cfg = match FileConfig::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sudixd: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime_dir = std::env::var("SUDIX_RUNTIME_DIR").unwrap_or_else(|_| "/run/sudix".into());
    let cfg = Config {
        socket_path: PathBuf::from(&runtime_dir).join("sudixd.sock"),
        agent_uids: file_cfg.agent_uids.clone(),
        policy: file_cfg.build_policy(),
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
