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

/// On-disk config file schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Allow rules as token lists, e.g. `[["pacman", "-S", "**"], ...]`.
    pub allow: Vec<Vec<String>>,
    /// Hard-denied program basenames.
    pub hard_deny: Vec<String>,
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
        for (i, toks) in self.allow.iter().enumerate() {
            Rule::new(toks.iter().map(String::as_str))
                .map_err(|e| ConfigError::Invalid(format!("allow rule {i}: {e}")))?;
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
            .map(|toks| Rule::new(toks.iter().map(String::as_str)).expect("already validated"))
            .collect();
        Policy::new(allow, self.hard_deny.clone())
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

# Allow rules: each entry is an argv token list. The first token is the
# program basename; `*` matches one argument; `**` matches zero-or-more
# trailing arguments (only valid as the last token).
allow = [
  ["pacman", "-S", "**"],
  ["pacman", "-Syu", "**"],
  ["systemctl", "status", "*"],
  ["systemctl", "restart", "*"],
  ["id"],
]

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
allow = [["pacman", "-S", "**"], ["id"]]
hard_deny = ["dd"]
"#,
        )
        .unwrap();
        let policy = cfg.build_policy();
        assert_eq!(
            policy.evaluate(&["pacman", "-S", "rg"].map(str::to_string)),
            Verdict::Allowed
        );
        assert_eq!(
            policy.evaluate(&["id"].map(str::to_string)),
            Verdict::Allowed
        );
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
allow = [["pacman", "**", "-S"]]
hard_deny = []
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
allow = [["id"]]
hard_deny = []
bogus_key = true
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
        assert_eq!(
            policy.evaluate(&argv(&["pacman", "-S", "rg"])),
            Verdict::Allowed
        );
        assert_eq!(policy.evaluate(&argv(&["id"])), Verdict::Allowed);
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
    fn perm_check_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"allow=[]\nhard_deny=[]\n").unwrap();
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
