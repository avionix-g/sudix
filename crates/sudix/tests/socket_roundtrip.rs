//! Component test: drive a real broker over a real unix socket.
//!
//! Exercises the parts `handle_request`'s unit tests can't: socket framing, the
//! `SO_PEERCRED` path (the test process is the peer, so its own uid is the
//! authorized one), and the client/server JSON contract end to end.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use sudix::approval::Approver;
use sudix::policy::{Policy, Rule};
use sudix::protocol::{Request, Response};
use sudix::scoping::RuleScope;
use sudix::server::{Config, serve};

/// Always-allow approver for the happy path.
struct AlwaysAllow;
impl Approver for AlwaysAllow {
    fn approve(&self, _req: &Request) -> bool {
        true
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
    stream.write_all(req.to_line().unwrap().as_bytes()).unwrap();
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
    }
}
