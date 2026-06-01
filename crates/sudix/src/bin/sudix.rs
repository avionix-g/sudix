//! `sudix` — the thin client a coding agent invokes in place of `sudo`.
//!
//! Usage:
//!     sudix [--reason "why"] -- <command> [args...]
//!
//! It connects to the broker socket, submits the command, and on approval
//! prints the command's stdout/stderr and exits with its exit code. The client
//! holds no credentials and makes no security decisions — it is pure transport.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use sudix::protocol::{Request, Response};

struct Args {
    reason: String,
    argv: Vec<String>,
}

/// Parse `[--reason TEXT] [--] CMD ARGS...`. The first non-flag token (or
/// everything after `--`) begins the command.
fn parse_args(mut raw: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut reason = "no reason given".to_string();
    let mut argv = Vec::new();

    while let Some(tok) = raw.next() {
        match tok.as_str() {
            "--reason" => {
                reason = raw.next().ok_or("--reason requires a value")?;
            }
            "--" => {
                argv.extend(raw.by_ref());
                break;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            other => {
                argv.push(other.to_string());
                argv.extend(raw.by_ref());
                break;
            }
        }
    }

    if argv.is_empty() {
        return Err("no command given".into());
    }
    Ok(Args { reason, argv })
}

fn run() -> Result<i32, String> {
    let args = parse_args(std::env::args().skip(1))?;
    let socket_path =
        std::env::var("SUDIX_SOCKET").unwrap_or_else(|_| "/run/sudix/sudixd.sock".into());

    let cwd =
        std::env::current_dir().map_or_else(|_| ".".into(), |p| p.to_string_lossy().into_owned());

    let req = Request {
        argv: args.argv,
        cwd,
        reason: args.reason,
    };

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("cannot reach broker at {socket_path}: {e}"))?;
    let line = req.to_line().map_err(|e| e.to_string())?;
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(&stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| e.to_string())?;
    let resp = Response::from_line(&resp_line).map_err(|e| e.to_string())?;

    match resp {
        Response::Approved {
            exit_code,
            stdout,
            stderr,
        } => {
            print!("{stdout}");
            eprint!("{stderr}");
            Ok(exit_code)
        }
        Response::Denied { why } => {
            eprintln!("sudix: denied: {why}");
            Ok(126)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        // Propagate the command's own exit code (clamped to u8 like a shell).
        Ok(code) => ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1)),
        Err(e) => {
            eprintln!("sudix: {e}");
            ExitCode::from(125)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Result<Args, String> {
        parse_args(parts.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn parses_reason_then_double_dash_command() {
        let a = args(&["--reason", "install rg", "--", "pacman", "-S", "ripgrep"]).unwrap();
        assert_eq!(a.reason, "install rg");
        assert_eq!(a.argv, vec!["pacman", "-S", "ripgrep"]);
    }

    #[test]
    fn bare_command_without_double_dash() {
        let a = args(&["id"]).unwrap();
        assert_eq!(a.argv, vec!["id"]);
        assert_eq!(a.reason, "no reason given");
    }

    #[test]
    fn flags_after_command_belong_to_the_command() {
        // Once the command starts, `-S` is the command's flag, not ours.
        let a = args(&["pacman", "-S", "ripgrep"]).unwrap();
        assert_eq!(a.argv, vec!["pacman", "-S", "ripgrep"]);
    }

    #[test]
    fn missing_command_is_an_error() {
        assert!(args(&["--reason", "x"]).is_err());
        assert!(args(&[]).is_err());
    }

    #[test]
    fn unknown_leading_flag_is_an_error() {
        assert!(args(&["--bogus", "id"]).is_err());
    }
}
