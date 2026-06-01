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
use sudix::policy::{Policy, Rule};
use sudix::protocol::{Hello, Request, Response};
use sudix::scoping::RuleScope;
use sudix::server::{Config, serve};

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

fn spawn_broker(dir: &std::path::Path, agent_uids: Vec<u32>) -> std::path::PathBuf {
    let socket_path = dir.join("sock");
    let cfg = Config {
        socket_path: socket_path.clone(),
        agent_uids,
        policy: Policy::new(vec![Rule::new(["echo", "**"]).unwrap()], vec!["dd".into()]),
        rule_scopes: vec![RuleScope {
            cache_ttl_secs: 0,
            rate_per_min: 0,
        }],
        audit_path: dir.join("audit.log"),
    };
    thread::spawn(move || {
        // Static approver lives for the thread's lifetime. `serve` only
        // returns on a bind error; the test fails via `wait_for_socket` if so.
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
    let socket = spawn_broker(dir.path(), vec![uid]);

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
    let socket = spawn_broker(dir.path(), vec![uid]);

    assert!(matches!(
        send(&socket, &req(&["rm", "-rf", "/"])),
        Response::Denied { .. }
    ));
}

#[test]
fn wrong_uid_is_rejected_before_policy() {
    // Authorize a uid that is not ours; the broker must refuse our connection
    // on peer-cred grounds alone, without consulting policy.
    let our_uid = nix::unistd::getuid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let socket = spawn_broker(dir.path(), vec![our_uid.wrapping_add(1)]);

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
    let socket_path = dir.path().join("sock");
    let concurrent = Arc::new(AtomicU32::new(0));
    let max_seen = Arc::new(AtomicU32::new(0));
    let approver = SlowApprover {
        concurrent: Arc::clone(&concurrent),
        max_seen: Arc::clone(&max_seen),
    };

    let cfg = Config {
        socket_path: socket_path.clone(),
        agent_uids: vec![uid],
        policy: Policy::new(vec![Rule::new(["echo", "**"]).unwrap()], vec!["dd".into()]),
        rule_scopes: vec![RuleScope {
            cache_ttl_secs: 0,
            rate_per_min: 0,
        }],
        audit_path: dir.path().join("audit.log"),
    };
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

    // All connections should complete successfully.
    for resp in &responses {
        assert!(matches!(resp, Response::Approved { .. }), "got: {resp:?}");
    }

    // Approval is serialized: at most one dialog outstanding at a time.
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
    let socket_path = dir.path().join("sock");

    let cfg = Config {
        socket_path: socket_path.clone(),
        agent_uids: vec![uid],
        policy: Policy::new(vec![Rule::new(["echo", "**"]).unwrap()], vec!["dd".into()]),
        rule_scopes: vec![],
        audit_path: dir.path().join("audit.log"),
    };
    thread::spawn(move || {
        drop(serve(&cfg, &AlwaysAllow));
    });
    wait_for_socket(&socket_path);

    // Write 1 MiB of 'x' with no newline — must be denied, not buffered.
    // The daemon may close the write end after hitting the cap, so broken-pipe
    // errors on our side are expected and harmless.
    let mut stream = UnixStream::connect(&socket_path).expect("connect");
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
