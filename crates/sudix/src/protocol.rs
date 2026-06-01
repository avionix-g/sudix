//! Wire protocol between the `sudix` client and the `sudixd` broker.
//!
//! One request → one response, each a single line of JSON terminated by `\n`.
//! Keeping the framing this dumb makes the protocol trivial to audit and to
//! exercise from tests or a raw `socat` session.

use serde::{Deserialize, Serialize};

/// A request to run a privileged command, submitted by the agent.
///
/// The broker — not the client — decides what actually runs: `argv` is matched
/// against server-side policy and, if approved, executed verbatim. `cwd` and
/// `reason` are advisory context shown to the human approver; they are never
/// trusted for an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The command and its arguments, e.g. `["pacman", "-S", "ripgrep"]`.
    /// Must be non-empty; `argv[0]` is the program.
    pub argv: Vec<String>,
    /// Working directory the agent intends the command to run in.
    pub cwd: String,
    /// Human-readable justification, surfaced in the approval dialog.
    pub reason: String,
}

/// The broker's verdict and (if it ran) the command's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Response {
    /// The command matched policy, was approved by the human, and executed.
    Approved {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// The command was rejected before execution. `why` is safe to show the
    /// agent; it never leaks approver state beyond the denial reason.
    Denied { why: String },
}

impl Request {
    /// Serialize to a single newline-terminated JSON line.
    ///
    /// # Errors
    /// Returns an error if serialization fails (should not happen for these
    /// owned, plain types).
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Parse from a single JSON line (trailing newline optional).
    ///
    /// # Errors
    /// Returns an error if the line is not valid JSON for a [`Request`].
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim_end())
    }
}

impl Response {
    /// Serialize to a single newline-terminated JSON line.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Parse from a single JSON line (trailing newline optional).
    ///
    /// # Errors
    /// Returns an error if the line is not valid JSON for a [`Response`].
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_a_line() {
        let req = Request {
            argv: vec!["pacman".into(), "-S".into(), "ripgrep".into()],
            cwd: "/home/adam/repos/hexapod".into(),
            reason: "install ripgrep".into(),
        };
        let line = req.to_line().unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(Request::from_line(&line).unwrap(), req);
    }

    #[test]
    fn response_round_trips_and_tags_the_decision() {
        let ok = Response::Approved {
            exit_code: 0,
            stdout: "done".into(),
            stderr: String::new(),
        };
        let line = ok.to_line().unwrap();
        assert!(line.contains("\"decision\":\"approved\""));
        assert_eq!(Response::from_line(&line).unwrap(), ok);

        let no = Response::Denied {
            why: "not allowed".into(),
        };
        assert!(no.to_line().unwrap().contains("\"decision\":\"denied\""));
    }

    #[test]
    fn from_line_tolerates_missing_trailing_newline() {
        let raw = r#"{"argv":["id"],"cwd":"/","reason":"x"}"#;
        assert_eq!(Request::from_line(raw).unwrap().argv, vec!["id"]);
    }
}
