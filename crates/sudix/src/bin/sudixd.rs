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
//!   `sudixd enroll`          — generate a TOTP secret and print the provisioning URI.

use std::path::PathBuf;
use std::process::ExitCode;

use listenfd::ListenFd;

use sudix::approval::{AgentApprover, approver_for};
use sudix::config::{self, FileConfig};
use sudix::server::{serve, serve_on, serve_on_with_registry, serve_with_registry};

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    if raw_args.first().map(String::as_str) == Some("default-config") {
        print!("{}", config::default_config_toml());
        return ExitCode::SUCCESS;
    }

    if raw_args.first().map(String::as_str) == Some("enroll") {
        let force = raw_args.contains(&"--force".to_string());
        return cmd_enroll(force);
    }

    if let Some(other) = raw_args.first()
        && other != "--"
    {
        eprintln!("sudixd: unknown subcommand: {other}");
        eprintln!("usage: sudixd [default-config | enroll [--force]]");
        return ExitCode::FAILURE;
    }

    match run_daemon() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sudixd: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_daemon() -> std::io::Result<()> {
    use std::io::Error;
    use std::sync::Arc;

    use sudix::scoping::RuleScope;
    use sudix::server::{Config, PolicyBundle, ReloadCtx};

    let config_path =
        std::env::var("SUDIX_CONFIG").unwrap_or_else(|_| config::DEFAULT_CONFIG_PATH.to_string());
    let config_path = std::path::PathBuf::from(config_path);

    let file_cfg = FileConfig::load(&config_path).map_err(|e| Error::other(e.to_string()))?;

    let initial_hash = config::config_hash(&config_path).ok();

    let static_approver = approver_for(
        &file_cfg.approval.method,
        file_cfg.approval.totp_secret_path.as_deref(),
        true,
    )
    .map_err(|e| Error::other(format!("approval setup failed: {e}")))?;

    let runtime_dir = std::env::var("SUDIX_RUNTIME_DIR").unwrap_or_else(|_| "/run/sudix".into());
    let rule_scopes = file_cfg
        .rule_scoping()
        .into_iter()
        .map(|(ttl, rate)| RuleScope {
            cache_ttl_secs: ttl,
            rate_per_min: rate,
        })
        .collect();
    let bundle = PolicyBundle {
        policy: file_cfg.build_policy(),
        rule_scopes,
        agent_uids: file_cfg.agent_uids.clone(),
    };
    let cfg = Arc::new(Config::new(
        PathBuf::from(&runtime_dir).join("sudixd.sock"),
        PathBuf::from(&runtime_dir).join("audit.log"),
        ReloadCtx {
            config_path,
            enforce_perms: true,
        },
        bundle,
        initial_hash,
    ));

    if let Some(approver) = static_approver {
        // Static approver (totp): use the standard serve path.
        if let Some(listener) = try_systemd_listener() {
            eprintln!(
                "sudixd: using systemd-passed socket (agent uids: {:?})",
                cfg.current
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .agent_uids
            );
            serve_on(&cfg, &listener, approver.as_ref())
        } else {
            if let Some(parent) = cfg.socket_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            serve(&cfg, approver.as_ref())
        }
    } else {
        // Agent method: share registry between AgentApprover and server.
        let registry = std::sync::Arc::new((
            std::sync::Mutex::new(std::collections::HashMap::new()),
            std::sync::Condvar::new(),
        ));
        let approver = AgentApprover {
            registry: std::sync::Arc::clone(&registry),
            register_wait: std::time::Duration::from_secs(10),
            approval_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
        };

        if let Some(listener) = try_systemd_listener() {
            eprintln!(
                "sudixd: using systemd-passed socket (agent uids: {:?})",
                cfg.current
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .agent_uids
            );
            serve_on_with_registry(&cfg, &listener, &approver, &registry)
        } else {
            if let Some(parent) = cfg.socket_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            serve_with_registry(&cfg, &approver, &registry)
        }
    }
}

/// Return the first Unix listener handed in by systemd socket activation, if any.
fn try_systemd_listener() -> Option<std::os::unix::net::UnixListener> {
    let mut lfd = ListenFd::from_env();
    lfd.take_unix_listener(0).ok().flatten()
}

fn cmd_enroll(force: bool) -> ExitCode {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use totp_rs::{Algorithm, TOTP};

    let config_path =
        std::env::var("SUDIX_CONFIG").unwrap_or_else(|_| config::DEFAULT_CONFIG_PATH.to_string());

    let Some(secret_path) = get_totp_secret_path(&config_path) else {
        eprintln!("sudixd enroll: config must have approval.totp_secret_path set to a file path");
        return ExitCode::FAILURE;
    };

    if !force && std::path::Path::new(&secret_path).exists() {
        eprintln!("sudixd enroll: {secret_path} already exists; use --force to overwrite");
        return ExitCode::FAILURE;
    }

    let secret = totp_rs::Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();
    let secret_bytes = secret.to_bytes().unwrap();

    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o400)
        .open(&secret_path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(secret_b32.as_bytes()) {
                eprintln!("sudixd enroll: write failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("sudixd enroll: cannot create {secret_path}: {e}");
            return ExitCode::FAILURE;
        }
    }

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("sudix".to_string()),
        "sudixd".to_string(),
    )
    .unwrap();
    let uri = totp.get_url();
    println!("Secret written to: {secret_path}");
    println!("Provisioning URI (scan with your authenticator app):");
    println!("{uri}");
    ExitCode::SUCCESS
}

fn get_totp_secret_path(config_path: &str) -> Option<String> {
    let cfg = FileConfig::load(std::path::Path::new(config_path)).ok()?;
    cfg.approval.totp_secret_path
}
