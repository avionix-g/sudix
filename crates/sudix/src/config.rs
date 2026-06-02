//! Load and validate the root-owned `/etc/sudix/policy.toml` config file.

use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::policy::{Policy, Rule};

/// Default config file path (overridden by `$SUDIX_CONFIG`).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/sudix/policy.toml";

/// Errors that can occur while loading or validating config.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Parse(e) => write!(f, "parse error: {e}"),
            Self::Invalid(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Which human-approval mechanism the daemon uses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMethod {
    Agent,
    Totp,
}

/// `[approval]` table in the config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Which approver to use.
    pub method: ApprovalMethod,
    /// Required when `method = "totp"`: path to the root-owned secret file.
    pub totp_secret_path: Option<String>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            method: ApprovalMethod::Agent,
            totp_secret_path: None,
        }
    }
}

/// A single deny rule entry: just a regex pattern.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyEntry {
    pub argv: String,
}

/// A single allow rule entry with optional scoping knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// Regex pattern matched against the shell-quoted, basename-normalized argv rendering.
    pub argv: String,
    /// After one approval, auto-approve the identical argv for this many
    /// seconds. `0` (the default) means always prompt.
    #[serde(default)]
    pub cache_ttl_secs: u64,
    /// Maximum number of approvals per minute for this rule. `0` (the default)
    /// means unlimited.
    #[serde(default)]
    pub rate_per_min: u32,
}

/// On-disk config file schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Deny rules (evaluated before allow). Absent = empty list.
    #[serde(default)]
    pub deny: Vec<DenyEntry>,
    /// Allow rules.
    pub allow: Vec<AllowEntry>,
    /// UIDs permitted to submit requests (agent service accounts).
    pub agent_uids: Vec<u32>,
    /// UIDs whose live presence the approval step is meant to prove.
    pub approver_uids: Vec<u32>,
    /// Approval method configuration.
    #[serde(default)]
    pub approval: ApprovalConfig,
}

impl FileConfig {
    /// Load and validate the config from `path`.
    ///
    /// Production code passes `enforce_perms = true`; tests may pass `false` to
    /// avoid the root-ownership check on tempfiles they own.
    ///
    /// # Errors
    /// Returns `ConfigError::Io` if the file cannot be read,
    /// `ConfigError::Parse` if TOML parsing fails,
    /// `ConfigError::Invalid` if a rule is malformed or permissions are wrong.
    pub fn load_with_checks(path: &Path, enforce_perms: bool) -> Result<Self, ConfigError> {
        if enforce_perms {
            check_file_permissions(path)?;
        }
        let raw = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load with full permission enforcement (production entry point).
    ///
    /// # Errors
    /// See [`Self::load_with_checks`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::load_with_checks(path, true)
    }

    /// Validate rule semantics and return errors with their rule index.
    fn validate(&self) -> Result<(), ConfigError> {
        for (i, entry) in self.deny.iter().enumerate() {
            Rule::new(&entry.argv)
                .map_err(|e| ConfigError::Invalid(format!("deny rule {i}: {e}")))?;
        }
        for (i, entry) in self.allow.iter().enumerate() {
            Rule::new(&entry.argv)
                .map_err(|e| ConfigError::Invalid(format!("allow rule {i}: {e}")))?;
        }

        if self.agent_uids.is_empty() {
            return Err(ConfigError::Invalid("agent_uids must not be empty".into()));
        }
        if self.approver_uids.is_empty() {
            return Err(ConfigError::Invalid(
                "approver_uids must not be empty".into(),
            ));
        }

        if self.approval.method == ApprovalMethod::Totp && self.approval.totp_secret_path.is_none()
        {
            return Err(ConfigError::Invalid(
                "method=\"totp\" requires approval.totp_secret_path".into(),
            ));
        }

        Ok(())
    }

    /// Build a [`Policy`] from the validated config.
    ///
    /// # Panics
    /// Cannot panic: `validate()` guarantees all rules are well-formed before
    /// this is called.
    #[must_use]
    pub fn build_policy(&self) -> Policy {
        let deny = self
            .deny
            .iter()
            .map(|e| Rule::new(&e.argv).expect("already validated"))
            .collect();
        let allow = self
            .allow
            .iter()
            .map(|e| Rule::new(&e.argv).expect("already validated"))
            .collect();
        Policy::new(deny, allow)
    }

    /// Return the scoping parameters (ttl, rate) for each allow rule in order.
    #[must_use]
    pub fn rule_scoping(&self) -> Vec<(u64, u32)> {
        self.allow
            .iter()
            .map(|e| (e.cache_ttl_secs, e.rate_per_min))
            .collect()
    }
}

/// Return the mtime of `path` for reload comparisons.
///
/// # Errors
/// Propagates any `std::io::Error` from `metadata`.
pub fn config_mtime(path: &Path) -> std::io::Result<std::time::SystemTime> {
    std::fs::metadata(path)?.modified()
}

/// Refuse to trust a config file that is group- or world-writable, or not
/// owned by root. A world-writable policy file is a privilege-escalation hole.
fn check_file_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    if meta.mode() & 0o022 != 0 {
        return Err(ConfigError::Invalid(format!(
            "{} is group- or world-writable; refusing to load (fix: chmod o-w,g-w)",
            path.display()
        )));
    }
    if meta.uid() != 0 {
        return Err(ConfigError::Invalid(format!(
            "{} is not owned by root (uid {}); refusing to load",
            path.display(),
            meta.uid()
        )));
    }
    Ok(())
}

/// Return a TOML string for the default policy. `default-config` prints this.
#[must_use]
pub fn default_config_toml() -> String {
    r#"# sudix policy — generated by `sudixd default-config`
#
# This file must be owned by root and not group- or world-writable.
#   sudo chown root:root /etc/sudix/policy.toml
#   sudo chmod 644 /etc/sudix/policy.toml   # or 640; not 666/664
#
# Rules match a REGEX (Rust `regex` crate syntax) against a rendered command
# string: argv[0] is reduced to its basename, every token is shell-quoted, and
# the tokens are joined with single spaces. Example renderings:
#   /usr/bin/pacman -S ripgrep   ->  pacman -S ripgrep
#   rm "-rf /"                    ->  rm '-rf /'
#
# Patterns are UNANCHORED: `id` also matches `id -u` (renders "id -u").
# Anchor with ^ and $ to match an exact command, e.g. "^id$".
# `.*` matches everything — use it for an explicit allow-all or deny-all.
#
# deny is checked first and OVERRIDES allow.

# Programs/commands refused regardless of allow rules.
deny = [
  { argv = "^(sh|bash|zsh|fish)( |$)" },
  { argv = "^(dd|mkfs|fdisk|parted)( |$)" },
  { argv = "^(tee|chmod|chown)( |$)" },
  { argv = "^(visudo|su|sudo)( |$)" },
  { argv = "^env( |$)" },
  { argv = "^(vi|vim|nano)( |$)" },
  { argv = "^(python|perl)( |$)" },
]

# Replace 1000 with the uid(s) of the agent and the human approver.
agent_uids    = [1000]
approver_uids = [1000]

# Allow rules. Optional per-rule scoping (both default to 0 = off):
#   cache_ttl_secs = 300   # auto-approve identical argv for N seconds after one approval
#   rate_per_min   = 10    # max executions/min; over limit → denied
allow = [
  { argv = "^pacman -S " },
  { argv = "^pacman -Syu( |$)" },
  { argv = "^systemctl status \\S+$" },
  { argv = "^systemctl restart \\S+$" },
  { argv = "^id$" },
]

[approval]
# "agent" (per-user sudix-agent in the graphical session) or "totp" (headless).
method = "agent"
# totp_secret_path = "/etc/sudix/totp.key"   # required when method = "totp"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::policy::Verdict;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    fn load_str(toml: &str) -> Result<FileConfig, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        drop(f);
        FileConfig::load_with_checks(&path, false)
    }

    #[test]
    fn round_trip_allow_deny() {
        let cfg = load_str(
            r#"
deny = [ { argv = "^dd( |$)" } ]
agent_uids = [1000]
approver_uids = [1000]

allow = [
  { argv = "^pacman -S " },
  { argv = "^id$" },
]
"#,
        )
        .unwrap();
        let policy = cfg.build_policy();
        assert!(matches!(
            policy.evaluate(&["pacman", "-S", "rg"].map(str::to_string)),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            policy.evaluate(&["id"].map(str::to_string)),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            policy.evaluate(&["dd", "if=/dev/zero"].map(str::to_string)),
            Verdict::Denied { .. }
        ));
        assert!(matches!(
            policy.evaluate(&["curl", "http://x"].map(str::to_string)),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn deny_overrides_allow_when_in_both() {
        let cfg = load_str(
            r#"
deny = [ { argv = "^id$" } ]
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]
"#,
        )
        .unwrap();
        let policy = cfg.build_policy();
        assert!(matches!(
            policy.evaluate(&["id"].map(str::to_string)),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn invalid_deny_regex_is_config_error() {
        let err = load_str(
            r#"
deny = [ { argv = "(unclosed" } ]
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("deny rule 0"), "expected rule index in: {msg}");
    }

    #[test]
    fn invalid_allow_regex_is_config_error() {
        let err = load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "(unclosed" } ]
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("allow rule 0"),
            "expected rule index in: {msg}"
        );
    }

    #[test]
    fn deny_all_denies_otherwise_allowed() {
        let cfg = load_str(
            r#"
deny = [ { argv = ".*" } ]
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]
"#,
        )
        .unwrap();
        let policy = cfg.build_policy();
        assert!(matches!(
            policy.evaluate(&["id"].map(str::to_string)),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn unknown_key_is_a_parse_error() {
        let err = load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
bogus_key = true

allow = [ { argv = "^id$" } ]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got: {err}");
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = FileConfig::load(Path::new("/no/such/file/policy.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)), "got: {err}");
    }

    #[test]
    fn default_config_parses_and_matches_old_policy() {
        let toml = default_config_toml();
        let cfg: FileConfig = toml::from_str(&toml).expect("default config must parse");
        cfg.validate().expect("default config must validate");
        let policy = cfg.build_policy();

        assert!(matches!(
            policy.evaluate(&argv(&["pacman", "-S", "rg"])),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            policy.evaluate(&argv(&["id"])),
            Verdict::Allowed { .. }
        ));
        // Denied by deny list.
        assert!(matches!(
            policy.evaluate(&argv(&["bash", "-c", "rm -rf /"])),
            Verdict::Denied { .. }
        ));
        // Not on allowlist.
        assert!(matches!(
            policy.evaluate(&argv(&["rm", "-rf", "/"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn zenity_method_no_longer_parses() {
        let err = load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]

[approval]
method = "zenity"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got: {err}");
    }

    #[test]
    fn agent_method_parses() {
        load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]

[approval]
method = "agent"
"#,
        )
        .unwrap();
    }

    #[test]
    fn totp_method_parses() {
        let cfg = load_str(
            r#"
agent_uids = [2000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]

[approval]
method = "totp"
totp_secret_path = "/etc/sudix/totp.key"
"#,
        )
        .unwrap();
        assert_eq!(cfg.approval.method, ApprovalMethod::Totp);
    }

    #[test]
    fn totp_method_without_secret_path_is_invalid() {
        let err = load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]

[approval]
method = "totp"
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("totp_secret_path"),
            "expected totp_secret_path error in: {msg}"
        );
    }

    #[test]
    fn bad_method_string_is_parse_error() {
        let err = load_str(
            r#"
agent_uids = [1000]
approver_uids = [1000]
allow = [ { argv = "^id$" } ]

[approval]
method = "pigeons"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got: {err}");
    }

    #[test]
    fn perm_check_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"agent_uids=[1000]\napprover_uids=[1000]\nallow=[{argv=\"^id$\"}]\n")
            .unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = FileConfig::load_with_checks(&path, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("world-writable") || msg.contains("group- or world-writable"),
            "expected perm error in: {msg}"
        );
    }
}
