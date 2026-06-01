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

/// One audit record. `outcome` is a short tag: `approved`, `denied-policy`,
/// `denied-user`, or `executed`-with-exit-code is folded into `outcome`.
#[derive(Debug, Serialize)]
struct Entry<'a> {
    unix_secs: u64,
    caller_uid: u32,
    argv: &'a [String],
    cwd: &'a str,
    reason: &'a str,
    outcome: &'a str,
}

/// Append a single audit entry. Best-effort: a logging failure is returned to
/// the caller, which logs it but does not change the security decision.
///
/// # Errors
/// Returns any I/O error from opening or writing the log file.
pub fn record(log_path: &Path, caller_uid: u32, req: &Request, outcome: &str) -> io::Result<()> {
    let entry = Entry {
        unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        caller_uid,
        argv: &req.argv,
        cwd: &req.cwd,
        reason: &req.reason,
        outcome,
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

        record(&log, 1000, &req, "approved").unwrap();
        record(&log, 1000, &req, "denied-policy").unwrap();

        let body = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["caller_uid"], 1000);
        assert_eq!(first["outcome"], "approved");
        assert_eq!(first["argv"][0], "id");
    }
}
