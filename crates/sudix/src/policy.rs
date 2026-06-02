//! Server-side authorization policy.
//!
//! This is the security boundary the agent cannot forge: it runs inside the
//! root daemon and decides whether a requested `argv` is even *eligible* for
//! human approval. The model is deny-by-default — deny rules are evaluated
//! first, then allow rules; a request must match an allow rule and must not
//! match any deny rule, or it is rejected before any dialog is shown.
//!
//! Each rule is a regex matched against a canonical rendering of the argv:
//!   - `argv[0]` is reduced to its basename (path-spoofing resistance);
//!   - every token (including the basename) is shell-quoted via POSIX quoting;
//!   - tokens are joined with single spaces.
//!
//! Patterns are unanchored by default; anchor with `^`/`$` as needed.
//! `.*` matches every command.

use std::path::Path;

use regex::Regex;

/// Verdict returned by [`Policy::evaluate`].
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The command is permitted; `rule_index` is the 0-based index into the
    /// allow array (used for scoping lookups).
    Allowed { rule_index: usize },
    /// The command is refused for the given human-readable reason.
    Denied { reason: String },
}

/// Render `argv` into the canonical string a policy regex is matched against:
/// `basename(argv[0])` + each token shell-quoted, joined with single spaces.
///
/// Ordinary tokens (no shell-significant chars) are left unquoted, keeping
/// regexes readable. Tokens with spaces/quotes/globs are POSIX-quoted.
#[must_use]
pub fn render_command(argv: &[String]) -> String {
    let mut parts = Vec::with_capacity(argv.len());
    for (i, tok) in argv.iter().enumerate() {
        let effective = if i == 0 { basename(tok) } else { tok.as_str() };
        // shlex::try_quote only fails on strings containing NUL, which cannot
        // appear in a String. Fall back to the raw token (unreachable in practice).
        let quoted = shlex::try_quote(effective).unwrap_or_else(|_| effective.into());
        parts.push(quoted.into_owned());
    }
    parts.join(" ")
}

/// A single compiled policy rule (deny or allow).
#[derive(Clone)]
pub struct Rule {
    re: Regex,
    src: String,
}

impl Rule {
    /// Compile a rule from a regex pattern string.
    ///
    /// # Errors
    /// Returns the regex compile error message if the pattern is invalid.
    pub fn new(pattern: &str) -> Result<Self, String> {
        Regex::new(pattern)
            .map(|re| Self {
                re,
                src: pattern.to_owned(),
            })
            .map_err(|e| e.to_string())
    }

    /// The original pattern string (for error messages / debugging).
    #[must_use]
    pub fn src(&self) -> &str {
        &self.src
    }

    fn is_match(&self, rendered: &str) -> bool {
        self.re.is_match(rendered)
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rule({:?})", self.src)
    }
}

/// The complete policy: an ordered deny list evaluated before an ordered allow
/// list. Deny takes precedence — a command matching any deny rule is refused
/// even if it would also match an allow rule.
#[derive(Debug, Clone)]
pub struct Policy {
    deny: Vec<Rule>,
    allow: Vec<Rule>,
}

impl Policy {
    /// Construct a policy from deny and allow rule lists.
    #[must_use]
    pub fn new(deny: Vec<Rule>, allow: Vec<Rule>) -> Self {
        Self { deny, allow }
    }

    /// Evaluate a request's argv against the policy.
    ///
    /// Pipeline:
    /// 1. Empty argv → `Denied`.
    /// 2. Render the command once via [`render_command`].
    /// 3. If any deny rule matches → `Denied`.
    /// 4. If any allow rule matches → `Allowed { rule_index }`.
    /// 5. No match → `Denied`.
    #[must_use]
    pub fn evaluate(&self, argv: &[String]) -> Verdict {
        if argv.is_empty() {
            return Verdict::Denied {
                reason: "empty argv".into(),
            };
        }
        let rendered = render_command(argv);
        if self.deny.iter().any(|r| r.is_match(&rendered)) {
            return Verdict::Denied {
                reason: "command matches deny rule".into(),
            };
        }
        if let Some(idx) = self.allow.iter().position(|r| r.is_match(&rendered)) {
            Verdict::Allowed { rule_index: idx }
        } else {
            Verdict::Denied {
                reason: "command does not match any allow rule".into(),
            }
        }
    }
}

/// File-name component of a program token (`/usr/bin/pacman` -> `pacman`).
fn basename(prog: &str) -> &str {
    Path::new(prog)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    fn policy() -> Policy {
        Policy::new(
            vec![Rule::new("^(dd|sh|bash)( |$)").unwrap()],
            vec![
                Rule::new("^pacman -S ").unwrap(),
                Rule::new(r"^systemctl status \S+$").unwrap(),
                Rule::new("^id$").unwrap(),
            ],
        )
    }

    // --- render_command tests ---

    #[test]
    fn render_basename_normalization() {
        let rendered = render_command(&argv(&["/usr/bin/pacman", "-S", "ripgrep"]));
        assert_eq!(rendered, "pacman -S ripgrep");
    }

    #[test]
    fn render_space_in_arg_gets_quoted() {
        // ["rm", "-rf /"] → rm '-rf /'
        let rendered = render_command(&argv(&["rm", "-rf /"]));
        assert_eq!(rendered, "rm '-rf /'");
    }

    #[test]
    fn render_two_rm_shapes_are_distinct() {
        let with_space = render_command(&argv(&["rm", "-rf /"]));
        let without_space = render_command(&argv(&["rm", "-rf", "/"]));
        assert_ne!(with_space, without_space);
        assert_eq!(without_space, "rm -rf /");
    }

    // --- deny/allow precedence ---

    #[test]
    fn deny_overrides_allow() {
        let p = Policy::new(
            vec![Rule::new("^bash( |$)").unwrap()],
            vec![Rule::new("^bash ").unwrap()],
        );
        assert!(matches!(
            p.evaluate(&argv(&["bash", "-c", "rm -rf /"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn allow_all_rule() {
        let p = Policy::new(vec![], vec![Rule::new(".*").unwrap()]);
        assert!(matches!(
            p.evaluate(&argv(&["anything", "goes"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn deny_all_rule() {
        let p = Policy::new(
            vec![Rule::new(".*").unwrap()],
            vec![Rule::new(".*").unwrap()],
        );
        assert!(matches!(
            p.evaluate(&argv(&["echo", "hi"])),
            Verdict::Denied { .. }
        ));
    }

    // --- anchoring ---

    #[test]
    fn anchored_id_matches_bare_id_only() {
        let p = Policy::new(vec![], vec![Rule::new("^id$").unwrap()]);
        assert!(matches!(
            p.evaluate(&argv(&["id"])),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            p.evaluate(&argv(&["id", "-u"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn unanchored_prefix_match() {
        let p = Policy::new(vec![], vec![Rule::new("pacman -S ").unwrap()]);
        assert!(matches!(
            p.evaluate(&argv(&["pacman", "-S", "rg"])),
            Verdict::Allowed { .. }
        ));
    }

    // --- path spoofing ---

    #[test]
    fn path_spoofing_still_blocked() {
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/dd", "if=/dev/zero"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn path_to_allowed_program_still_allowed() {
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/pacman", "-S", "ripgrep"])),
            Verdict::Allowed { .. }
        ));
    }

    // --- basic policy behavior ---

    #[test]
    fn unknown_command_denied_by_default() {
        assert!(matches!(
            policy().evaluate(&argv(&["curl", "http://evil"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn empty_argv_denied() {
        assert!(matches!(
            policy().evaluate(&[]),
            Verdict::Denied { reason } if reason == "empty argv"
        ));
    }

    #[test]
    fn invalid_regex_returns_err() {
        assert!(Rule::new("(unclosed").is_err());
    }

    // --- rule_index correctness ---

    #[test]
    fn rule_index_reflects_allow_array_position() {
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-S", "rg"])),
            Verdict::Allowed { rule_index: 0 }
        ));
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd"])),
            Verdict::Allowed { rule_index: 1 }
        ));
        assert!(matches!(
            policy().evaluate(&argv(&["id"])),
            Verdict::Allowed { rule_index: 2 }
        ));
    }

    // --- spirit of old positional tests ---

    #[test]
    fn systemctl_status_one_arg() {
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd"])),
            Verdict::Allowed { .. }
        ));
        // extra arg renders "systemctl status sshd extra" — \S+$ fails to anchor
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd", "extra"])),
            Verdict::Denied { .. }
        ));
    }
}
