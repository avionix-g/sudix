//! Append-only audit log.
//!
//! Every request the daemon evaluates — allowed or denied — is recorded as one
//! JSON line. The log is written by the (root) daemon, so it reflects what the
//! broker actually did, not what the caller claims. This is the record you read
//! after the fact to answer "what did the agent run as root?".

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::protocol::Request;

/// The outcome of a broker request. Used in audit records.
///
/// Exhaustive list of tags written to the audit log:
/// - `denied-empty` — argv was empty
/// - `denied-reason` — reason field was too long
/// - `denied-policy` — policy refused the command
/// - `denied-cwd` — cwd was invalid or non-existent
/// - `denied-rate` — rate limit exceeded
/// - `denied-user` — human denied the dialog
/// - `approved-cached` — cache hit; executed without prompting (includes exit code)
/// - `executed` — freshly approved and executed (includes exit code)
/// - `execute-error` — spawn or I/O failure after approval
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    DeniedEmpty,
    DeniedReason,
    DeniedPolicy,
    DeniedCwd,
    DeniedRate,
    DeniedUser,
    ApprovedCached { exit_code: i32 },
    Executed { exit_code: i32 },
    ExecuteError,
}

impl Outcome {
    fn as_tag_and_exit(self) -> (&'static str, Option<i32>) {
        match self {
            Outcome::DeniedEmpty => ("denied-empty", None),
            Outcome::DeniedReason => ("denied-reason", None),
            Outcome::DeniedPolicy => ("denied-policy", None),
            Outcome::DeniedCwd => ("denied-cwd", None),
            Outcome::DeniedRate => ("denied-rate", None),
            Outcome::DeniedUser => ("denied-user", None),
            Outcome::ApprovedCached { exit_code } => ("approved-cached", Some(exit_code)),
            Outcome::Executed { exit_code } => ("executed", Some(exit_code)),
            Outcome::ExecuteError => ("execute-error", None),
        }
    }
}

/// One audit record.
#[derive(Debug, Serialize)]
struct Entry<'a> {
    unix_secs: u64,
    caller_uid: u32,
    argv: &'a [String],
    cwd: &'a str,
    reason: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

/// Append a single audit entry. Best-effort: a logging failure is returned to
/// the caller, which logs it but does not change the security decision.
///
/// # Errors
/// Returns any I/O error from opening or writing the log file.
pub fn record(log_path: &Path, caller_uid: u32, req: &Request, outcome: Outcome) -> io::Result<()> {
    let (tag, exit_code) = outcome.as_tag_and_exit();
    let entry = Entry {
        unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        caller_uid,
        argv: &req.argv,
        cwd: &req.cwd,
        reason: &req.reason,
        outcome: tag,
        exit_code,
    };
    let mut line =
        serde_json::to_string(&entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    f.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_appends_one_json_line_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "check".into(),
            otp: None,
        };

        record(&log, 1000, &req, Outcome::Executed { exit_code: 0 }).unwrap();
        record(&log, 1000, &req, Outcome::DeniedPolicy).unwrap();

        let body = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["caller_uid"], 1000);
        assert_eq!(first["outcome"], "executed");
        assert_eq!(first["exit_code"], 0);
        assert_eq!(first["argv"][0], "id");
    }
}
