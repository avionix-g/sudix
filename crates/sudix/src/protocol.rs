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
    /// TOTP code for headless approval. Never audited (it is a live secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
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
    /// An internal error prevented the broker from deciding. This is not a
    /// denial — the human was not consulted.
    Error { why: String },
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

/// The first line sent by a client on every new connection, declaring its role.
///
/// - `Command` is the existing one-shot flow: send a request, get a response.
/// - `RegisterAgent` starts a persistent approver session; the uid is taken
///   from `SO_PEERCRED` and no further auth data is needed on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Hello {
    Command(Request),
    RegisterAgent,
}

impl Hello {
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
    /// Returns an error if the line is not valid JSON for a [`Hello`].
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim_end())
    }
}

/// A prompt sent from the broker to a registered agent, asking for a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub argv: Vec<String>,
    pub cwd: String,
    pub reason: String,
}

impl Prompt {
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
    /// Returns an error if the line is not valid JSON for a [`Prompt`].
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line.trim_end())
    }
}

/// The agent's response to a [`Prompt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    Error { why: String },
}

impl Verdict {
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
    /// Returns an error if the line is not valid JSON for a [`Verdict`].
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
            otp: None,
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

        let err = Response::Error {
            why: "no agent running".into(),
        };
        let err_line = err.to_line().unwrap();
        assert!(err_line.contains("\"decision\":\"error\""));
        assert_eq!(Response::from_line(&err_line).unwrap(), err);
    }

    #[test]
    fn from_line_tolerates_missing_trailing_newline() {
        let raw = r#"{"argv":["id"],"cwd":"/","reason":"x"}"#;
        assert_eq!(Request::from_line(raw).unwrap().argv, vec!["id"]);
    }

    #[test]
    fn request_with_otp_round_trips() {
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "totp test".into(),
            otp: Some("123456".into()),
        };
        let line = req.to_line().unwrap();
        assert!(line.contains("\"otp\""));
        assert_eq!(Request::from_line(&line).unwrap(), req);
    }

    #[test]
    fn old_request_without_otp_deserializes_as_none() {
        let raw = r#"{"argv":["id"],"cwd":"/","reason":"x"}"#;
        let req = Request::from_line(raw).unwrap();
        assert_eq!(req.otp, None);
    }

    #[test]
    fn otp_none_is_not_serialized() {
        let req = Request {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "x".into(),
            otp: None,
        };
        let line = req.to_line().unwrap();
        assert!(!line.contains("otp"));
    }

    #[test]
    fn hello_command_round_trips() {
        let req = Request {
            argv: vec!["pacman".into(), "-S".into(), "ripgrep".into()],
            cwd: "/home/adam".into(),
            reason: "install".into(),
            otp: None,
        };
        let hello = Hello::Command(req.clone());
        let line = hello.to_line().unwrap();
        assert!(line.contains("\"kind\":\"command\""));
        assert_eq!(Hello::from_line(&line).unwrap(), hello);
    }

    #[test]
    fn hello_register_agent_round_trips() {
        let hello = Hello::RegisterAgent;
        let line = hello.to_line().unwrap();
        assert!(line.contains("\"kind\":\"register_agent\""));
        assert_eq!(Hello::from_line(&line).unwrap(), hello);
    }

    #[test]
    fn prompt_round_trips() {
        let p = Prompt {
            argv: vec!["id".into()],
            cwd: "/".into(),
            reason: "test".into(),
        };
        let line = p.to_line().unwrap();
        assert_eq!(Prompt::from_line(&line).unwrap(), p);
    }

    #[test]
    fn verdict_variants_round_trip() {
        for v in [
            Verdict::Allow,
            Verdict::Deny,
            Verdict::Error { why: "oops".into() },
        ] {
            let line = v.to_line().unwrap();
            assert_eq!(Verdict::from_line(&line).unwrap(), v);
        }
        assert!(
            Verdict::Allow
                .to_line()
                .unwrap()
                .contains("\"verdict\":\"allow\"")
        );
        assert!(
            Verdict::Deny
                .to_line()
                .unwrap()
                .contains("\"verdict\":\"deny\"")
        );
    }
}
