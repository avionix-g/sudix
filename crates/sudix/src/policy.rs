//! Server-side authorization policy.
//!
//! This is the security boundary the agent cannot forge: it runs inside the
//! root daemon and decides whether a requested `argv` is even *eligible* for
//! human approval. The model is deny-by-default — deny rules are evaluated
//! first, then allow rules; a request must match an allow rule and must not
//! match any deny rule, or it is rejected before any dialog is shown.
//!
//! Each rule is an ordered list of [`TokenMatcher`]s, one per shell token:
//!   - `argv[0]` is basename-normalized before matching (path-spoofing
//!     resistance); subsequent tokens are matched verbatim.
//!   - [`TokenMatcher::Literal`] matches one token byte-for-byte.
//!   - [`TokenMatcher::Regex`] matches one token against a pattern anchored
//!     as `^(?:PATTERN)$` at compile time; the operator writes only the inner
//!     pattern.
//!   - [`TokenMatcher::Rest`] (final position only) matches zero or more
//!     trailing tokens.
//!
//! Arguments containing control characters (bytes < 0x20 or 0x7f) are
//! refused outright before any rule is consulted.

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

impl Verdict {
    /// Returns `true` if this verdict is [`Verdict::Allowed`].
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// A single token matcher within a rule.
#[derive(Clone)]
pub enum TokenMatcher {
    /// Matches exactly one token, byte-for-byte equal to the stored string.
    Literal(String),
    /// Matches exactly one token against a pre-anchored regex (`^(?:src)$`).
    Regex { re: regex::Regex, src: String },
    /// Matches zero or more trailing tokens. Valid only as the final matcher.
    Rest,
}

impl TokenMatcher {
    /// Construct a `Literal` matcher.
    #[must_use]
    pub fn literal(s: impl Into<String>) -> Self {
        Self::Literal(s.into())
    }

    /// Construct an anchored `Regex` matcher.
    ///
    /// The pattern is automatically wrapped as `^(?:PATTERN)$`.
    ///
    /// # Errors
    /// Returns the regex compile error if the pattern is invalid.
    pub fn regex(pattern: &str) -> Result<Self, String> {
        let anchored = format!("^(?:{pattern})$");
        Regex::new(&anchored)
            .map(|re| Self::Regex {
                re,
                src: pattern.to_owned(),
            })
            .map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for TokenMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(s) => write!(f, "{s:?}"),
            Self::Regex { src, .. } => write!(f, "{{re:{src}}}"),
            Self::Rest => write!(f, "{{rest}}"),
        }
    }
}

/// A single compiled policy rule (deny or allow): an ordered list of token matchers.
#[derive(Clone, Debug)]
pub struct Rule {
    matchers: Vec<TokenMatcher>,
}

impl Rule {
    /// Construct a rule from a list of token matchers.
    ///
    /// # Errors
    /// - `"rule must have at least one matcher"` if the list is empty.
    /// - `` "`rest` is only valid as the final matcher" `` if `Rest` appears
    ///   in a non-final position.
    pub fn new(matchers: Vec<TokenMatcher>) -> Result<Self, String> {
        if matchers.is_empty() {
            return Err("rule must have at least one matcher".into());
        }
        for (i, m) in matchers.iter().enumerate() {
            if matches!(m, TokenMatcher::Rest) && i != matchers.len() - 1 {
                return Err("`rest` is only valid as the final matcher".into());
            }
        }
        Ok(Self { matchers })
    }

    /// Returns `true` if `argv` matches this rule.
    ///
    /// `argv[0]` is basename-normalized; all other positions are matched
    /// verbatim. The caller guarantees `argv` is non-empty and control-char-free.
    #[must_use]
    pub fn is_match(&self, argv: &[String]) -> bool {
        let mut argv_idx = 0usize;
        for matcher in &self.matchers {
            match matcher {
                TokenMatcher::Rest => {
                    // Matches zero or more trailing tokens. Always succeeds
                    // (final-only guaranteed by Rule::new).
                    return true;
                }
                TokenMatcher::Literal(s) => {
                    if argv_idx >= argv.len() {
                        return false;
                    }
                    if effective(argv, argv_idx) != s.as_str() {
                        return false;
                    }
                }
                TokenMatcher::Regex { re, .. } => {
                    if argv_idx >= argv.len() {
                        return false;
                    }
                    if !re.is_match(effective(argv, argv_idx)) {
                        return false;
                    }
                }
            }
            argv_idx += 1;
        }
        // All matchers consumed without a Rest: require exact length.
        argv_idx == argv.len()
    }

    /// Render the matcher list as a human-readable string for deny reasons.
    /// Example: `pacman -S {re:\S+} {rest}`
    #[must_use]
    pub fn describe(&self) -> String {
        self.matchers
            .iter()
            .map(|m| match m {
                TokenMatcher::Literal(s) => s.clone(),
                TokenMatcher::Regex { src, .. } => format!("{{re:{src}}}"),
                TokenMatcher::Rest => "{rest}".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The full policy: deny rules checked before allow rules.
#[derive(Clone, Debug)]
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
    /// 2. Any token contains a control character → `Denied`.
    /// 3. First matching deny rule → `Denied` with rule index and description.
    /// 4. First matching allow rule → `Allowed { rule_index }`.
    /// 5. No match → `Denied`.
    #[must_use]
    pub fn evaluate(&self, argv: &[String]) -> Verdict {
        if argv.is_empty() {
            return Verdict::Denied {
                reason: "empty argv".into(),
            };
        }
        if has_control_char(argv) {
            return Verdict::Denied {
                reason: "control character in argument".into(),
            };
        }
        if let Some((i, rule)) = self.deny.iter().enumerate().find(|(_, r)| r.is_match(argv)) {
            return Verdict::Denied {
                reason: format!("denied by rule {i}: {}", rule.describe()),
            };
        }
        if let Some(idx) = self.allow.iter().position(|r| r.is_match(argv)) {
            Verdict::Allowed { rule_index: idx }
        } else {
            Verdict::Denied {
                reason: "no allow rule matched".into(),
            }
        }
    }
}

/// Returns the effective token at position `i`: basename-normalized for i==0,
/// verbatim otherwise.
fn effective(argv: &[String], i: usize) -> &str {
    if i == 0 { basename(&argv[0]) } else { &argv[i] }
}

/// Returns `true` if any token in `argv` contains a byte < 0x20 or == 0x7f.
fn has_control_char(argv: &[String]) -> bool {
    argv.iter()
        .any(|tok| tok.bytes().any(|b| b < 0x20 || b == 0x7f))
}

/// Returns the final path component of `s`, or `s` itself if there is no `/`.
fn basename(s: &str) -> &str {
    Path::new(s)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// Policy used by most tests:
    ///   deny:  [{re:dd} {rest}], [{re:sh|bash} {rest}]
    ///   allow: [pacman -S {rest}], [systemctl status {re:\S+}], [id]
    fn policy() -> Policy {
        Policy::new(
            vec![
                Rule::new(vec![TokenMatcher::regex("dd").unwrap(), TokenMatcher::Rest]).unwrap(),
                Rule::new(vec![
                    TokenMatcher::regex("sh|bash").unwrap(),
                    TokenMatcher::Rest,
                ])
                .unwrap(),
            ],
            vec![
                Rule::new(vec![
                    TokenMatcher::literal("pacman"),
                    TokenMatcher::literal("-S"),
                    TokenMatcher::Rest,
                ])
                .unwrap(),
                Rule::new(vec![
                    TokenMatcher::literal("systemctl"),
                    TokenMatcher::literal("status"),
                    TokenMatcher::regex(r"\S+").unwrap(),
                ])
                .unwrap(),
                Rule::new(vec![TokenMatcher::literal("id")]).unwrap(),
            ],
        )
    }

    // --- Literal program match ---

    #[test]
    fn literal_program_match_exact() {
        assert!(matches!(
            policy().evaluate(&argv(&["id"])),
            Verdict::Allowed { rule_index: 2 }
        ));
    }

    #[test]
    fn literal_program_match_extra_arg_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["id", "-u"])),
            Verdict::Denied { .. }
        ));
    }

    // --- Basename normalization ---

    #[test]
    fn basename_normalization_allowed() {
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/pacman", "-S", "rg"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn basename_normalization_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/dd", "if=/dev/zero"])),
            Verdict::Denied { .. }
        ));
    }

    // --- Rest tail ---

    #[test]
    fn rest_tail_multiple_args() {
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-S", "a", "b"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn rest_tail_zero_args() {
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-S"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn rest_tail_missing_literal_denied() {
        // pacman without -S: literal "-S" at index 1 is unmatched
        assert!(matches!(
            policy().evaluate(&argv(&["pacman"])),
            Verdict::Denied { .. }
        ));
    }

    // --- Allow-all via lone Rest ---

    #[test]
    fn allow_all_via_lone_rest() {
        let p = Policy::new(vec![], vec![Rule::new(vec![TokenMatcher::Rest]).unwrap()]);
        assert!(matches!(
            p.evaluate(&argv(&["anything", "goes"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn allow_all_empty_argv_still_denied() {
        let p = Policy::new(vec![], vec![Rule::new(vec![TokenMatcher::Rest]).unwrap()]);
        assert!(matches!(
            p.evaluate(&[]),
            Verdict::Denied { reason } if reason == "empty argv"
        ));
    }

    // --- Per-token regex anchored ---

    #[test]
    fn regex_token_anchored_exact_match() {
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd"])),
            Verdict::Allowed { rule_index: 1 }
        ));
    }

    #[test]
    fn regex_token_anchored_extra_arg_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd", "extra"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn regex_token_space_in_arg_denied() {
        // "a b" contains a space; \S+ rejects it
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "a b"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn regex_anchored_no_prefix_match() {
        let p = Policy::new(
            vec![],
            vec![
                Rule::new(vec![
                    TokenMatcher::literal("x"),
                    TokenMatcher::regex("foo").unwrap(),
                ])
                .unwrap(),
            ],
        );
        // "foobar" does not match anchored ^(?:foo)$
        assert!(matches!(
            p.evaluate(&argv(&["x", "foobar"])),
            Verdict::Denied { .. }
        ));
        // exact "foo" matches
        assert!(matches!(
            p.evaluate(&argv(&["x", "foo"])),
            Verdict::Allowed { .. }
        ));
    }

    // --- rm/confirm non-collision ---

    #[test]
    fn rm_deny_does_not_deny_confirm() {
        let p = Policy::new(
            vec![Rule::new(vec![TokenMatcher::literal("rm"), TokenMatcher::Rest]).unwrap()],
            vec![Rule::new(vec![TokenMatcher::literal("confirm"), TokenMatcher::Rest]).unwrap()],
        );
        // deny rule ["rm", {rest}] must NOT fire for ["confirm", "x"]
        assert!(matches!(
            p.evaluate(&argv(&["confirm", "x"])),
            Verdict::Allowed { .. }
        ));
    }

    // --- Control-char denial ---

    #[test]
    fn control_char_in_argv0_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["id\n-u"])),
            Verdict::Denied { reason } if reason.contains("control character")
        ));
    }

    #[test]
    fn control_char_in_later_arg_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["echo", "a\tb"])),
            Verdict::Denied { reason } if reason.contains("control character")
        ));
    }

    // --- Empty-token matching ---

    #[test]
    fn empty_token_length_mismatch_denied() {
        assert!(matches!(
            policy().evaluate(&argv(&["id", ""])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn explicit_empty_literal_allowed() {
        let p = Policy::new(
            vec![],
            vec![
                Rule::new(vec![
                    TokenMatcher::literal("echo"),
                    TokenMatcher::literal(""),
                ])
                .unwrap(),
            ],
        );
        assert!(matches!(
            p.evaluate(&argv(&["echo", ""])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn nonempty_regex_rejects_empty_token() {
        let p = Policy::new(
            vec![],
            vec![
                Rule::new(vec![
                    TokenMatcher::literal("echo"),
                    TokenMatcher::regex(r"\S+").unwrap(),
                ])
                .unwrap(),
            ],
        );
        assert!(matches!(
            p.evaluate(&argv(&["echo", ""])),
            Verdict::Denied { .. }
        ));
    }

    // --- Rest placement validation ---

    #[test]
    fn rest_non_final_is_err() {
        assert!(Rule::new(vec![TokenMatcher::Rest, TokenMatcher::literal("x")]).is_err());
    }

    #[test]
    fn rest_final_is_ok() {
        assert!(Rule::new(vec![TokenMatcher::literal("x"), TokenMatcher::Rest]).is_ok());
    }

    #[test]
    fn empty_matcher_list_is_err() {
        assert!(Rule::new(vec![]).is_err());
    }

    // --- Regex anchoring implicit ---

    #[test]
    fn regex_anchoring_is_implicit() {
        // Pattern "foo" must not prefix-match "foobar"
        let r = Rule::new(vec![
            TokenMatcher::literal("x"),
            TokenMatcher::regex("foo").unwrap(),
        ])
        .unwrap();
        assert!(!r.is_match(&argv(&["x", "foobar"])));
        assert!(r.is_match(&argv(&["x", "foo"])));
    }

    // --- Regex constructor error ---

    #[test]
    fn invalid_regex_returns_err() {
        assert!(TokenMatcher::regex("(unclosed").is_err());
    }

    // --- Deny reason is actionable ---

    #[test]
    fn deny_reason_contains_rule_index_and_describe() {
        let verdict = policy().evaluate(&argv(&["dd", "if=/dev/zero"]));
        match verdict {
            Verdict::Denied { reason } => {
                assert!(
                    reason.contains("rule 0"),
                    "expected rule index in: {reason}"
                );
                assert!(reason.contains("dd"), "expected describe() in: {reason}");
            }
            Verdict::Allowed { .. } => panic!("expected denial"),
        }
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

    // --- Basic policy behavior ---

    #[test]
    fn empty_argv_denied() {
        assert!(matches!(
            policy().evaluate(&[]),
            Verdict::Denied { reason } if reason == "empty argv"
        ));
    }

    #[test]
    fn deny_overrides_allow() {
        let p = Policy::new(
            vec![Rule::new(vec![TokenMatcher::literal("bash"), TokenMatcher::Rest]).unwrap()],
            vec![Rule::new(vec![TokenMatcher::literal("bash"), TokenMatcher::Rest]).unwrap()],
        );
        assert!(matches!(
            p.evaluate(&argv(&["bash", "-c", "rm -rf /"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn deny_all_rule() {
        let p = Policy::new(
            vec![Rule::new(vec![TokenMatcher::Rest]).unwrap()],
            vec![Rule::new(vec![TokenMatcher::Rest]).unwrap()],
        );
        assert!(matches!(
            p.evaluate(&argv(&["echo", "hi"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn unknown_command_denied_by_default() {
        assert!(matches!(
            policy().evaluate(&argv(&["curl", "http://evil"])),
            Verdict::Denied { .. }
        ));
    }
}
