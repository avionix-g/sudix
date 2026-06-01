//! `sudix-agent` — per-user approval agent running in the graphical session.
//!
//! Connects to the broker, registers as the approver for the current user's
//! uid, then loops waiting for prompts and showing a zenity dialog for each.
//!
//! Runs as a systemd user service (`WantedBy=graphical-session.target`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use sudix::protocol::{Hello, Prompt};

fn run_agent(socket_path: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("cannot reach broker at {socket_path}: {e}"))?;

    let hello = Hello::RegisterAgent.to_line().map_err(|e| e.to_string())?;
    stream
        .write_all(hello.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    eprintln!("sudix-agent: registered with broker at {socket_path}");

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Err("broker closed the connection".into());
            }
            Err(e) => {
                return Err(format!("read error: {e}"));
            }
            Ok(_) => {}
        }

        let prompt = match Prompt::from_line(&line) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("sudix-agent: malformed prompt: {e}");
                continue;
            }
        };

        let verdict = sudix::approval::spawn_zenity(&prompt);

        let v_line = match verdict.to_line() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sudix-agent: failed to serialize verdict: {e}");
                continue;
            }
        };
        if let Err(e) = stream.write_all(v_line.as_bytes()) {
            return Err(format!("failed to send verdict: {e}"));
        }
        if let Err(e) = stream.flush() {
            return Err(format!("failed to flush verdict: {e}"));
        }
    }
}

const MAX_BACKOFF: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    let socket_path =
        std::env::var("SUDIX_SOCKET").unwrap_or_else(|_| "/run/sudix/sudixd.sock".into());

    // Reconnect with bounded backoff on broker disconnect.
    let mut backoff = Duration::from_secs(1);

    loop {
        match run_agent(&socket_path) {
            Ok(()) => {
                eprintln!("sudix-agent: disconnected, reconnecting…");
            }
            Err(e) => {
                eprintln!("sudix-agent: {e}, reconnecting in {}s…", backoff.as_secs());
            }
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {}
