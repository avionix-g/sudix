//! Server-side authorization policy.
//!
//! This is the security boundary the agent cannot forge: it runs inside the
//! root daemon and decides whether a requested `argv` is even *eligible* for
//! human approval. The model is deny-by-default — a request must match an
//! explicit allow rule, and must not touch the hard denylist, or it is
//! rejected before any dialog is shown.
//!
//! Matching is deliberately simple so the rules are auditable at a glance:
//! a rule is a sequence of tokens compared position-by-position against the
//! request's `argv`, with two wildcards:
//!   * `*`  matches exactly one argument (any value);
//!   * `**` matches zero or more *trailing* arguments (only valid as the last
//!     token).
//!
//! `argv[0]` (the program) is matched by its file name only, so `pacman` and
//! `/usr/bin/pacman` are equivalent — a caller cannot dodge a rule by spelling
//! the path differently.

use std::path::Path;

/// A single allow rule, e.g. `["pacman", "-S", "**"]`.
#[derive(Debug, Clone)]
pub struct Rule {
    tokens: Vec<String>,
}

/// The outcome of evaluating a request against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Eligible for approval — passes the allowlist and clears the denylist.
    /// `rule_index` is the 0-based index into the policy's allow list; the
    /// scoping engine uses it to look up per-rule TTL/rate knobs.
    Allowed { rule_index: usize },
    /// Rejected outright; `reason` is safe to surface to the caller.
    Denied { reason: String },
}

/// The complete policy: an ordered allowlist plus a hard, non-overridable
/// denylist of program basenames.
#[derive(Debug, Clone)]
pub struct Policy {
    allow: Vec<Rule>,
    /// Program basenames that are *always* refused even if an allow rule would
    /// otherwise match. These are commands whose blast radius is effectively
    /// unbounded regardless of arguments.
    hard_deny: Vec<String>,
}

impl Rule {
    /// Build a rule from tokens. `**`, if present, must be the final token.
    ///
    /// # Errors
    /// Returns an error if the rule is empty or `**` appears anywhere but last.
    pub fn new<I, S>(tokens: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let tokens: Vec<String> = tokens.into_iter().map(Into::into).collect();
        if tokens.is_empty() {
            return Err("rule must have at least one token (the program)".into());
        }
        if let Some(pos) = tokens.iter().position(|t| t == "**")
            && pos != tokens.len() - 1
        {
            return Err("`**` is only valid as the final token".into());
        }
        Ok(Self { tokens })
    }

    /// Does this rule match the given argv?
    fn matches(&self, argv: &[String]) -> bool {
        // Program: compare by basename so path spelling can't bypass a rule.
        let Some((req_prog, req_args)) = argv.split_first() else {
            return false;
        };
        let Some((want_prog, want_args)) = self.tokens.split_first() else {
            return false;
        };
        if basename(req_prog) != want_prog.as_str() {
            return false;
        }
        Self::match_args(want_args, req_args)
    }

    fn match_args(rule: &[String], args: &[String]) -> bool {
        let mut ri = 0;
        let mut ai = 0;
        while ri < rule.len() {
            match rule[ri].as_str() {
                "**" => return true, // matches all remaining args (incl. none)
                "*" => {
                    // matches exactly one arg, which must exist
                    if ai >= args.len() {
                        return false;
                    }
                }
                literal => {
                    if ai >= args.len() || args[ai] != literal {
                        return false;
                    }
                }
            }
            ri += 1;
            ai += 1;
        }
        // No more rule tokens: match iff all args were consumed.
        ai == args.len()
    }
}

impl Policy {
    /// Construct a policy from allow rules and hard-denied program basenames.
    #[must_use]
    pub fn new(allow: Vec<Rule>, hard_deny: Vec<String>) -> Self {
        Self { allow, hard_deny }
    }

    /// Evaluate a request's argv. Returns [`Verdict::Allowed`] only if the
    /// program is not hard-denied *and* some allow rule matches.
    #[must_use]
    pub fn evaluate(&self, argv: &[String]) -> Verdict {
        let Some(prog) = argv.first() else {
            return Verdict::Denied {
                reason: "empty argv".into(),
            };
        };
        let prog = basename(prog);
        if self.hard_deny.iter().any(|d| d == prog) {
            return Verdict::Denied {
                reason: format!("`{prog}` is on the hard denylist"),
            };
        }
        if let Some(idx) = self.allow.iter().position(|r| r.matches(argv)) {
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
            vec![
                Rule::new(["pacman", "-S", "**"]).unwrap(),
                Rule::new(["systemctl", "status", "*"]).unwrap(),
                Rule::new(["id"]).unwrap(),
            ],
            vec!["dd".into(), "sh".into(), "bash".into()],
        )
    }

    #[test]
    fn matches_trailing_wildcard() {
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-S", "ripgrep", "fd"])),
            Verdict::Allowed { .. }
        ));
        // `**` also matches zero trailing args.
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-S"])),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn single_wildcard_requires_exactly_one_arg() {
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd"])),
            Verdict::Allowed { .. }
        ));
        // Missing the one required arg → denied.
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status"])),
            Verdict::Denied { .. }
        ));
        // Extra arg beyond the single `*` → denied.
        assert!(matches!(
            policy().evaluate(&argv(&["systemctl", "status", "sshd", "extra"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn bare_program_rule_rejects_extra_args() {
        assert!(matches!(
            policy().evaluate(&argv(&["id"])),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            policy().evaluate(&argv(&["id", "-u"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn basename_normalization_blocks_path_spoofing() {
        // Absolute path to an allowed program still matches.
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/pacman", "-S", "ripgrep"])),
            Verdict::Allowed { .. }
        ));
        // ...and a path to a hard-denied program is still denied.
        assert!(matches!(
            policy().evaluate(&argv(&["/usr/bin/dd", "if=/dev/zero"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn hard_deny_overrides_allow() {
        // Even if we added an allow rule for bash, the denylist wins. Construct
        // such a policy explicitly to prove precedence.
        let p = Policy::new(
            vec![Rule::new(["bash", "**"]).unwrap()],
            vec!["bash".into()],
        );
        assert!(matches!(
            p.evaluate(&argv(&["bash", "-c", "rm -rf /"])),
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

    #[test]
    fn wrong_subcommand_denied() {
        // `pacman -R` is not `pacman -S`.
        assert!(matches!(
            policy().evaluate(&argv(&["pacman", "-R", "ripgrep"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn rule_construction_rejects_misplaced_double_star() {
        assert!(Rule::new(["pacman", "**", "-S"]).is_err());
        assert!(Rule::new(Vec::<String>::new()).is_err());
        assert!(Rule::new(["pacman", "**"]).is_ok());
    }
}
