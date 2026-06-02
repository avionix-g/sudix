//! Component test: drive a real broker over a real unix socket.
//!
//! Exercises the parts `handle_request`'s unit tests can't: socket framing, the
//! `SO_PEERCRED` path (the test process is the peer, so its own uid is the
//! authorized one), and the client/server JSON contract end to end.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use sudix::approval::{Approval, Approver};
use sudix::protocol::{Hello, Request, Response};
use sudix::server::{Config, ReloadCtx, bundle_from_file_cfg, serve};

/// Always-allow approver for the happy path.
struct AlwaysAllow;
impl Approver for AlwaysAllow {
    fn approve(&self, _caller_uid: u32, _req: &Request) -> Approval {
        Approval::Allowed
    }

    fn clone_box(&self) -> Box<dyn Approver> {
        Box::new(Self)
    }
}

/// Approver that counts concurrent calls (to verify serialization) and sleeps.
struct SlowApprover {
    concurrent: Arc<AtomicU32>,
    max_seen: Arc<AtomicU32>,
}

impl Approver for SlowApprover {
    fn approve(&self, _caller_uid: u32, _req: &Request) -> Approval {
        let c = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        let mut max = self.max_seen.load(Ordering::SeqCst);
        while c > max {
            match self
                .max_seen
                .compare_exchange(max, c, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => max = actual,
            }
        }
        thread::sleep(std::time::Duration::from_millis(20));
        self.concurrent.fetch_sub(1, Ordering::SeqCst);
        Approval::Allowed
    }

    fn clone_box(&self) -> Box<dyn Approver> {
        Box::new(Self {
            concurrent: Arc::clone(&self.concurrent),
            max_seen: Arc::clone(&self.max_seen),
        })
    }
}

/// Write a minimal config file to `dir` and load it, returning the path.
fn write_config(dir: &std::path::Path, uid: u32) -> std::path::PathBuf {
    use std::io::Write as _;
    let path = dir.join("policy.toml");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(
        f,
        r#"agent_uids = [{uid}]
approver_uids = [{uid}]
deny  = [ {{ argv = "^dd( |$)" }} ]
allow = [ {{ argv = "^echo( |$)" }} ]"#,
    )
    .unwrap();
    path
}

fn make_cfg(dir: &std::path::Path, uid: u32) -> Arc<Config> {
    let config_path = write_config(dir, uid);
    let fc = sudix::config::FileConfig::load_with_checks(&config_path, false).unwrap();
    let initial_mtime = sudix::config::config_mtime(&config_path).ok();
    let bundle = bundle_from_file_cfg(&fc);
    Arc::new(Config::new(
        dir.join("sock"),
        dir.join("audit.log"),
        ReloadCtx {
            config_path,
            enforce_perms: false,
        },
        bundle,
        initial_mtime,
    ))
}

fn spawn_broker(dir: &std::path::Path, uid: u32) -> std::path::PathBuf {
    let cfg = make_cfg(dir, uid);
    let socket_path = cfg.socket_path.clone();
    thread::spawn(move || {
        let _served = serve(&cfg, &AlwaysAllow);
    });
    wait_for_socket(&socket_path);
    socket_path
}

fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..200 {
        if UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("broker socket never appeared at {}", path.display());
}

fn send(socket: &std::path::Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream
        .write_all(Hello::Command(req.clone()).to_line().unwrap().as_bytes())
        .unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    Response::from_line(&line).expect("valid response")
}

fn req(parts: &[&str]) -> Request {
    Request {
        argv: parts.iter().map(|s| (*s).to_string()).collect(),
        cwd: ".".into(),
        reason: "integration".into(),
        otp: None,
    }
}

#[test]
fn approved_command_runs_over_the_socket() {
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_broker(dir.path(), uid);

    match send(&socket, &req(&["echo", "roundtrip"])) {
        Response::Approved {
            exit_code, stdout, ..
        } => {
            assert_eq!(exit_code, 0);
            assert_eq!(stdout.trim(), "roundtrip");
        }
        Response::Denied { why } => panic!("unexpected denial: {why}"),
        Response::Error { why } => panic!("unexpected error: {why}"),
    }
}

#[test]
fn policy_denied_command_is_refused_over_the_socket() {
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_broker(dir.path(), uid);

    assert!(matches!(
        send(&socket, &req(&["rm", "-rf", "/"])),
        Response::Denied { .. }
    ));
}

#[test]
fn wrong_uid_is_rejected_before_policy() {
    let our_uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_broker(dir.path(), our_uid.wrapping_add(1));

    match send(&socket, &req(&["echo", "hi"])) {
        Response::Denied { why } => assert!(why.contains("uid")),
        Response::Approved { .. } => panic!("connection from wrong uid was approved"),
        Response::Error { why } => panic!("unexpected error: {why}"),
    }
}

#[test]
fn concurrent_connections_are_handled_concurrently_with_serialized_approval() {
    const N: usize = 4;
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let config_path = write_config(dir.path(), uid);
    let fc = sudix::config::FileConfig::load_with_checks(&config_path, false).unwrap();
    let initial_mtime = sudix::config::config_mtime(&config_path).ok();
    let bundle = bundle_from_file_cfg(&fc);
    let socket_path = dir.path().join("sock");
    let concurrent = Arc::new(AtomicU32::new(0));
    let max_seen = Arc::new(AtomicU32::new(0));
    let approver = SlowApprover {
        concurrent: Arc::clone(&concurrent),
        max_seen: Arc::clone(&max_seen),
    };

    let cfg = Arc::new(Config::new(
        socket_path.clone(),
        dir.path().join("audit.log"),
        ReloadCtx {
            config_path,
            enforce_perms: false,
        },
        bundle,
        initial_mtime,
    ));
    thread::spawn(move || {
        drop(serve(&cfg, &approver));
    });
    wait_for_socket(&socket_path);

    let handles: Vec<_> = (0..N)
        .map(|_| {
            let sock = socket_path.clone();
            thread::spawn(move || send(&sock, &req(&["echo", "concurrent"])))
        })
        .collect();
    let responses: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for resp in &responses {
        assert!(matches!(resp, Response::Approved { .. }), "got: {resp:?}");
    }

    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "approval was not serialized"
    );
}

#[test]
fn oversized_request_is_refused_not_buffered() {
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_broker(dir.path(), uid);

    // Write 1 MiB of 'x' with no newline — must be denied, not buffered.
    let mut stream = UnixStream::connect(&socket).expect("connect");
    let payload = vec![b'x'; 1024 * 1024];
    drop(stream.write_all(&payload));
    drop(stream.flush());
    drop(stream.shutdown(std::net::Shutdown::Write));

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp = Response::from_line(&line).expect("valid response");
    assert!(
        matches!(resp, Response::Denied { ref why } if why.contains("too large")),
        "expected 'too large' denial, got: {resp:?}"
    );
}

/// Spawn a broker that uses an agent registry. Returns (`socket_path`, registry).
fn spawn_agent_broker(
    dir: &std::path::Path,
    uid: u32,
) -> (
    std::path::PathBuf,
    std::sync::Arc<sudix::approval::AgentRegistry>,
) {
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    use sudix::approval::{AgentApprover, AgentRegistry};
    use sudix::server::serve_on_with_registry;

    let config_path = write_config(dir, uid);
    let fc = sudix::config::FileConfig::load_with_checks(&config_path, false).unwrap();
    let initial_mtime = sudix::config::config_mtime(&config_path).ok();
    let bundle = bundle_from_file_cfg(&fc);
    let socket_path = dir.join("agent_sock");

    let registry: Arc<AgentRegistry> = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
    let registry2 = Arc::clone(&registry);
    let socket2 = socket_path.clone();
    let cfg = Arc::new(Config::new(
        socket_path.clone(),
        dir.join("agent_audit.log"),
        ReloadCtx {
            config_path,
            enforce_perms: false,
        },
        bundle,
        initial_mtime,
    ));
    thread::spawn(move || {
        let listener = std::os::unix::net::UnixListener::bind(&socket2).unwrap();
        let approver = AgentApprover {
            registry: Arc::clone(&registry2),
            register_wait: Duration::from_millis(200),
            approval_gate: Arc::new(std::sync::Mutex::new(())),
        };
        drop(serve_on_with_registry(
            &cfg, &listener, &approver, &registry2,
        ));
    });
    wait_for_socket(&socket_path);
    (socket_path, registry)
}

/// Register a fake agent that sends the given verdict for every prompt.
fn register_fake_agent(socket_path: &std::path::Path, verdict: sudix::protocol::Verdict) {
    use sudix::protocol::Hello;
    let socket_path = socket_path.to_path_buf();
    thread::spawn(move || {
        let stream = UnixStream::connect(&socket_path).expect("agent connect");
        let mut write_half = stream.try_clone().unwrap();
        write_half
            .write_all(Hello::RegisterAgent.to_line().unwrap().as_bytes())
            .unwrap();
        write_half.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let v_line = verdict.to_line().unwrap();
                    if write_half.write_all(v_line.as_bytes()).is_err() {
                        break;
                    }
                    write_half.flush().ok();
                    line.clear();
                }
            }
        }
    });
}

#[test]
fn agent_allows_command_end_to_end() {
    use sudix::protocol::Verdict;
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let (socket, _registry) = spawn_agent_broker(dir.path(), uid);
    register_fake_agent(&socket, Verdict::Allow);

    match send(&socket, &req(&["echo", "agent-allow"])) {
        Response::Approved {
            exit_code, stdout, ..
        } => {
            assert_eq!(exit_code, 0);
            assert_eq!(stdout.trim(), "agent-allow");
        }
        other => panic!("expected Approved, got: {other:?}"),
    }
}

#[test]
fn agent_denies_command_end_to_end() {
    use sudix::protocol::Verdict;
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let (socket, _registry) = spawn_agent_broker(dir.path(), uid);
    register_fake_agent(&socket, Verdict::Deny);

    match send(&socket, &req(&["echo", "agent-deny"])) {
        Response::Denied { .. } => {}
        other => panic!("expected Denied, got: {other:?}"),
    }
}

#[test]
fn no_agent_command_returns_response_error() {
    let uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    // spawn_agent_broker uses a 200ms register_wait; we don't register any agent
    let (socket, _registry) = spawn_agent_broker(dir.path(), uid);

    match send(&socket, &req(&["echo", "no-agent"])) {
        Response::Error { .. } => {}
        other => panic!("expected Error (no agent), got: {other:?}"),
    }
}
