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
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::Invalid(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

/// Approval method selector.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMethod {
    /// Desktop dialog via `zenity` (requires a GUI session).
    Zenity,
    /// Headless TOTP code in the request (implemented in Step 6).
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
            method: ApprovalMethod::Zenity,
            totp_secret_path: None,
        }
    }
}

/// A single allow rule entry in the config file.
///
/// Supports both the concise inline-array form (`["pacman", "-S", "**"]`) and
/// the table form (`{ argv = ["pacman", "-S", "**"], cache_ttl_secs = 300 }`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// The argv token pattern, e.g. `["pacman", "-S", "**"]`.
    pub argv: Vec<String>,
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
    /// Allow rules.
    pub allow: Vec<AllowEntry>,
    /// Hard-denied program basenames.
    pub hard_deny: Vec<String>,
    /// UIDs permitted to submit requests (agent service accounts).
    pub agent_uids: Vec<u32>,
    /// UIDs whose live presence the approval step is meant to prove.
    pub approver_uids: Vec<u32>,
    /// Approval method configuration.
    #[serde(default)]
    pub approval: ApprovalConfig,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

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

    /// Validate rule semantics (e.g. `**` placement) and return errors with
    /// their rule index so the operator can locate the offending line quickly.
    fn validate(&self) -> Result<(), ConfigError> {
        for (i, entry) in self.allow.iter().enumerate() {
            Rule::new(entry.argv.iter().map(String::as_str))
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

        // Disjoint UID sets with zenity is a misconfiguration: a desktop dialog
        // cannot prove that a human (who isn't the connecting agent) is present.
        let sets_disjoint = !self
            .agent_uids
            .iter()
            .any(|uid| self.approver_uids.contains(uid));
        if sets_disjoint && self.approval.method == ApprovalMethod::Zenity {
            return Err(ConfigError::Invalid(
                "agent_uids and approver_uids are disjoint but method=\"zenity\"; \
                 a desktop dialog cannot prove human presence for a separate agent uid — \
                 use method=\"totp\" for headless deployments"
                    .into(),
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
        let allow = self
            .allow
            .iter()
            .map(|e| Rule::new(e.argv.iter().map(String::as_str)).expect("already validated"))
            .collect();
        Policy::new(allow, self.hard_deny.clone())
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

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Starter config
// ---------------------------------------------------------------------------

/// Return a TOML string that exactly reproduces the compiled-in default
/// policy. This is the source of truth; `default-config` prints this.
#[must_use]
pub fn default_config_toml() -> String {
    r#"# sudix policy — generated by `sudixd default-config`
#
# This file must be owned by root and not group- or world-writable.
#   sudo chown root:root /etc/sudix/policy.toml
#   sudo chmod 644 /etc/sudix/policy.toml   # or 640; not 666/664

# Programs refused regardless of allow rules. Extend as needed.
hard_deny = [
  "sh", "bash", "zsh", "fish",
  "dd", "mkfs", "fdisk", "parted",
  "tee", "chmod", "chown",
  "visudo", "su", "sudo",
  "env",
  "vi", "vim", "nano",
  "python", "perl",
]

# Replace 1000 with the uid(s) of the agent and the human approver.
# For a single-user desktop deployment both lists contain the same uid.
agent_uids    = [1000]
approver_uids = [1000]

[approval]
# "zenity" (desktop dialog) or "totp" (headless; also set totp_secret_path).
method = "zenity"
# totp_secret_path = "/etc/sudix/totp.key"   # required when method = "totp"

# Allow rules. Each entry must have an `argv` token list. The first token is
# the program basename; `*` matches one argument; `**` matches zero-or-more
# trailing arguments (only valid as the last token).
#
# Optional per-rule scoping knobs (both default to 0 = "off"):
#   cache_ttl_secs = 300   # auto-approve same exact argv for N seconds after one approval
#   rate_per_min   = 10    # max approvals/min; over limit → denied (never auto-approved)

[[allow]]
argv = ["pacman", "-S", "**"]

[[allow]]
argv = ["pacman", "-Syu", "**"]

[[allow]]
argv = ["systemctl", "status", "*"]

[[allow]]
argv = ["systemctl", "restart", "*"]

[[allow]]
argv = ["id"]
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        // Use enforce_perms=false so tests can run unprivileged.
        FileConfig::load_with_checks(&path, false)
    }

    #[test]
    fn round_trip_allow_deny() {
        let cfg = load_str(
            r#"
hard_deny = ["dd"]
agent_uids = [1000]
approver_uids = [1000]

[[allow]]
argv = ["pacman", "-S", "**"]

[[allow]]
argv = ["id"]
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
    fn misplaced_double_star_is_invalid() {
        let err = load_str(
            r#"
hard_deny = []
agent_uids = [1000]
approver_uids = [1000]

[[allow]]
argv = ["pacman", "**", "-S"]
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
    fn unknown_key_is_a_parse_error() {
        let err = load_str(
            r#"
hard_deny = []
agent_uids = [1000]
approver_uids = [1000]
bogus_key = true

[[allow]]
argv = ["id"]
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
        // Must parse without error.
        let cfg: FileConfig = toml::from_str(&toml).expect("default config must parse");
        cfg.validate().expect("default config must validate");
        let policy = cfg.build_policy();

        // Allowed by old compiled policy.
        assert!(matches!(
            policy.evaluate(&argv(&["pacman", "-S", "rg"])),
            Verdict::Allowed { .. }
        ));
        assert!(matches!(
            policy.evaluate(&argv(&["id"])),
            Verdict::Allowed { .. }
        ));
        // Denied by hard denylist.
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
    fn disjoint_uids_with_zenity_is_invalid() {
        let err = load_str(
            r#"
hard_deny = []
agent_uids = [2000]
approver_uids = [1000]

[approval]
method = "zenity"

[[allow]]
argv = ["id"]
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("disjoint") || msg.contains("zenity"),
            "expected disjoint/zenity error in: {msg}"
        );
    }

    #[test]
    fn overlapping_uids_with_zenity_is_valid() {
        load_str(
            r#"
hard_deny = []
agent_uids = [1000]
approver_uids = [1000]

[approval]
method = "zenity"

[[allow]]
argv = ["id"]
"#,
        )
        .unwrap();
    }

    #[test]
    fn totp_method_parses() {
        let cfg = load_str(
            r#"
hard_deny = []
agent_uids = [2000]
approver_uids = [1000]

[approval]
method = "totp"
totp_secret_path = "/etc/sudix/totp.key"

[[allow]]
argv = ["id"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.approval.method, ApprovalMethod::Totp);
    }

    #[test]
    fn totp_method_without_secret_path_is_invalid() {
        let err = load_str(
            r#"
hard_deny = []
agent_uids = [1000]
approver_uids = [1000]

[approval]
method = "totp"

[[allow]]
argv = ["id"]
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
hard_deny = []
agent_uids = [1000]
approver_uids = [1000]

[approval]
method = "pigeons"

[[allow]]
argv = ["id"]
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
        f.write_all(b"hard_deny=[]\nagent_uids=[1000]\napprover_uids=[1000]\n")
            .unwrap();
        drop(f);
        // Make it world-writable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = FileConfig::load_with_checks(&path, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("world-writable") || msg.contains("group- or world-writable"),
            "expected perm error in: {msg}"
        );
    }
}
