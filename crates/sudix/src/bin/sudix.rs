//! `sudix` — request privileged command execution via the sudix broker.
//!
//! Usage:
//!     sudix [--reason TEXT] [--otp CODE] [--] <command> [args...]
//!     sudix -h | --help
//!
//! It connects to the broker socket, submits the command, and on approval
//! prints the command's stdout/stderr and exits with its exit code. The client
//! holds no credentials and makes no security decisions — it is pure transport.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use sudix::protocol::{Hello, Request, Response};

const HELP: &str = "\
sudix — request privileged command execution via the sudix broker.

Usage:
    sudix [--reason TEXT] [--otp CODE] [--] <command> [args...]
    sudix -h | --help

Options:
    --reason TEXT   Human-readable justification shown to the approver.
    --otp CODE      One-time code (when the broker uses TOTP approval).
    -h, --help      Show this help and exit.

The command after `--` (or the first non-flag token) is submitted to the
broker, which gates it through policy + human approval and, if approved,
runs it as root and relays its output and exit code.

Environment:
    SUDIX_SOCKET    Broker socket path (default: /run/sudix/sudixd.sock).
";

struct Args {
    reason: String,
    otp: Option<String>,
    argv: Vec<String>,
}

/// Parse `[-h | --help] [--reason TEXT] [--otp CODE] [--] CMD ARGS...`.
///
/// Returns `Ok(None)` when `-h`/`--help` is the leading flag (caller prints
/// help and exits 0). Returns `Ok(Some(args))` on success. Returns `Err` on
/// invalid input.
fn parse_args(mut raw: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut reason = "no reason given".to_string();
    let mut otp: Option<String> = None;
    let mut argv = Vec::new();

    while let Some(tok) = raw.next() {
        match tok.as_str() {
            "-h" | "--help" => {
                return Ok(None);
            }
            "--reason" => {
                reason = flag_value(&mut raw, "--reason")?;
            }
            "--otp" => {
                otp = Some(flag_value(&mut raw, "--otp")?);
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
    Ok(Some(Args { reason, otp, argv }))
}

/// Take the value following an option flag. Rejects `--` so it can't be silently
/// consumed as a value (`sudix --reason -- id` is an error, not "reason == --").
fn flag_value(raw: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    match raw.next() {
        Some(v) if v != "--" => Ok(v),
        Some(_) => Err(format!("{flag} requires a value (got `--`)")),
        None => Err(format!("{flag} requires a value")),
    }
}

fn run() -> Result<i32, String> {
    let Some(args) = parse_args(std::env::args().skip(1))? else {
        print!("{HELP}");
        return Ok(0);
    };
    let socket_path =
        std::env::var("SUDIX_SOCKET").unwrap_or_else(|_| "/run/sudix/sudixd.sock".into());

    let cwd =
        std::env::current_dir().map_or_else(|_| ".".into(), |p| p.to_string_lossy().into_owned());

    let req = Request {
        argv: args.argv,
        cwd,
        reason: args.reason,
        otp: args.otp,
    };

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("cannot reach broker at {socket_path}: {e}"))?;
    let line = Hello::Command(req).to_line().map_err(|e| e.to_string())?;
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
        Response::Error { why } => {
            eprintln!("sudix: error: {why}");
            Ok(125)
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

    fn args(parts: &[&str]) -> Result<Option<Args>, String> {
        parse_args(parts.iter().map(|s| (*s).to_string()))
    }

    fn args_unwrap(parts: &[&str]) -> Args {
        args(parts).unwrap().unwrap()
    }

    #[test]
    fn parses_reason_then_double_dash_command() {
        let a = args_unwrap(&["--reason", "install rg", "--", "pacman", "-S", "ripgrep"]);
        assert_eq!(a.reason, "install rg");
        assert_eq!(a.argv, vec!["pacman", "-S", "ripgrep"]);
    }

    #[test]
    fn bare_command_without_double_dash() {
        let a = args_unwrap(&["id"]);
        assert_eq!(a.argv, vec!["id"]);
        assert_eq!(a.reason, "no reason given");
    }

    #[test]
    fn flags_after_command_belong_to_the_command() {
        let a = args_unwrap(&["pacman", "-S", "ripgrep"]);
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

    #[test]
    fn otp_flag_before_command() {
        let a = args_unwrap(&["--otp", "123456", "--", "id"]);
        assert_eq!(a.otp, Some("123456".to_string()));
        assert_eq!(a.argv, vec!["id"]);
    }

    #[test]
    fn otp_flag_after_double_dash_belongs_to_command() {
        let a = args_unwrap(&["--", "myapp", "--otp", "999"]);
        assert_eq!(a.otp, None);
        assert_eq!(a.argv, vec!["myapp", "--otp", "999"]);
    }

    #[test]
    fn otp_missing_required_arg_is_an_error() {
        assert!(args(&["--otp"]).is_err());
    }

    #[test]
    fn double_dash_is_not_a_flag_value() {
        // `--` must terminate option parsing, not be swallowed as a value.
        assert!(args(&["--reason", "--", "id"]).is_err());
        assert!(args(&["--otp", "--", "id"]).is_err());
    }

    // --- help flag tests ---

    #[test]
    fn short_help_flag_returns_none() {
        assert!(matches!(args(&["-h"]), Ok(None)));
    }

    #[test]
    fn long_help_flag_returns_none() {
        assert!(matches!(args(&["--help"]), Ok(None)));
    }

    #[test]
    fn help_after_double_dash_is_command_arg() {
        let a = args_unwrap(&["--", "myapp", "--help"]);
        assert_eq!(a.argv, vec!["myapp", "--help"]);
    }

    #[test]
    fn help_after_command_start_is_command_arg() {
        let a = args_unwrap(&["myapp", "--help"]);
        assert_eq!(a.argv, vec!["myapp", "--help"]);
    }
}
