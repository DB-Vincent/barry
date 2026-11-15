//! Configuration loading.
//!
//! The file is deserialized into structs that reject unknown keys (#26). The
//! hand-rolled parser this replaced ignored anything it did not recognise, so a
//! misspelled `read_denny = [...]` left the credential paths unprotected with
//! no warning at all: the user believed they had configured a deny that never
//! existed.

use std::path::{Path, PathBuf};

use barry_policy::BashRule;
use barry_protocol::Decision;
use serde::Deserialize;
use thiserror::Error;

/// Errors from config loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config error in {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("config error in {path}: {message}")]
    Invalid { path: String, message: String },
}

/// User configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub default_model: String,
    pub max_turns: u64,
    /// Context window used for compaction heuristics (tokens).
    pub context_window: u64,
    /// Sandbox: whether bash commands may access the network.
    pub sandbox_network: bool,
    /// Filesystem: paths whose contents must never be read (expanded `~`,
    /// canonicalised where they exist).
    pub fs_read_deny: Vec<String>,
    /// Filesystem: path components that always require approval (e.g. `.git`,
    /// `.barry`, `.env`).
    pub fs_protected: Vec<String>,
    /// Whether tool results are redacted before they are sent to the model
    /// (#17). Off by default, which keeps BC-5.3: the model receives the real
    /// tool output and only the session log is redacted. Turn it on when the
    /// provider is remote and tool output may carry credentials.
    pub redact_tool_output: bool,
    /// Bash rules (`[[rule]]`), applied after the built-in defaults.
    pub rules: Vec<BashRule>,
    /// Hooks run around tool execution (PLAN 6.5).
    pub hooks: Vec<HookConfig>,
}

/// A single hook: `[[hooks.PreToolUse]]` in the config.
#[derive(Debug, Clone)]
pub struct HookConfig {
    /// Regex matched against the tool name (e.g. `bash|write`).
    pub matcher: String,
    /// Command + arguments to run.
    pub command: Vec<String>,
    /// Hook timeout in seconds.
    pub timeout_secs: u64,
    /// If true, a non-zero / timeout result blocks the tool; otherwise just
    /// a warning is emitted.
    pub fail_closed: bool,
}

/// Read-deny paths used when the config does not say otherwise (#10).
///
/// These are where credentials live, and a read result goes to the model, so
/// `cat ~/.ssh/id_rsa` must not be allowed just because `cat` is a safe
/// command. Entries are paths, not globs: a read is denied for anything under
/// one of them.
///
/// Setting `fs.read_deny = []` in the config file opts out entirely.
pub fn default_read_deny() -> Vec<String> {
    [
        "~/.ssh",
        "~/.aws",
        "~/.config/gcloud",
        "~/.kube",
        "~/.docker",
        "~/.gnupg",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Protected path components used when the config does not say otherwise.
/// A write to one of these always asks (PLAN 6.1.1, #10).
pub fn default_protected() -> Vec<String> {
    [".git", ".barry", ".env"]
        .into_iter()
        .map(String::from)
        .collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 32_768,
            // Deny by default: network access and reading credential
            // directories are opt-in, because the output goes to the model
            // and the model may be remote (#10).
            sandbox_network: false,
            fs_read_deny: default_read_deny(),
            fs_protected: default_protected(),
            redact_tool_output: false,
            rules: vec![],
            hooks: vec![],
        }
    }
}

/// Where the config file lives when `$BARRY_CONFIG` is unset (#27).
///
/// `$XDG_CONFIG_HOME/barry/config.toml`, falling back to
/// `~/.config/barry/config.toml` as the XDG spec says.
pub fn default_config_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir).join("barry/config.toml"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/barry/config.toml"))
}

impl Config {
    /// Load the user config.
    ///
    /// `$BARRY_CONFIG` wins whenever it is set; otherwise the XDG path is
    /// tried (#27). `Ok(None)` means there is no config file, so the built-in
    /// defaults apply; a file that exists but does not parse is an error.
    pub fn load() -> Result<Option<Self>, ConfigError> {
        match std::env::var("BARRY_CONFIG") {
            Ok(path) => Self::load_from(Path::new(&path)),
            Err(_) => match default_config_path() {
                Some(path) => Self::load_from(&path),
                None => Ok(None),
            },
        }
    }

    /// Load from an explicit path. A missing file is not an error.
    pub fn load_from(path: &Path) -> Result<Option<Self>, ConfigError> {
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let file: FileConfig = toml::from_str(&content).map_err(|source| ConfigError::Toml {
            path: path.display().to_string(),
            source,
        })?;

        let path_label = path.display().to_string();
        let invalid = |message: String| ConfigError::Invalid {
            path: path_label.clone(),
            message,
        };

        let mut rules = Vec::with_capacity(file.rule.len());
        for rule in file.rule {
            if rule.id.is_empty() || rule.pattern.is_empty() {
                return Err(invalid(format!(
                    "rule {}: both `id` and `match` must be non-empty",
                    rule.id
                )));
            }
            let decision = match rule.decision.as_str() {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny {
                    reason: format!("rule {} denies this command", rule.id),
                },
                "ask" => Decision::Ask {
                    reason: format!("rule {} requires approval", rule.id),
                },
                other => {
                    return Err(invalid(format!(
                        "rule {}: unknown decision {other:?} (expected allow, ask or deny)",
                        rule.id
                    )))
                }
            };
            rules.push(BashRule {
                id: rule.id,
                r#match: rule.pattern,
                decision,
            });
        }

        // A hook the user wrote must not be dropped because half of it is
        // missing, for the same reason a malformed rule is an error.
        let mut hooks = Vec::with_capacity(file.hooks.pre_tool_use.len());
        for hook in file.hooks.pre_tool_use {
            if hook.matcher.is_empty() || hook.command.is_empty() {
                return Err(invalid(
                    "hooks.PreToolUse: `matcher` and `command` are both required".to_string(),
                ));
            }
            hooks.push(HookConfig {
                matcher: hook.matcher,
                command: hook.command,
                timeout_secs: hook.timeout_secs,
                fail_closed: hook.fail_closed,
            });
        }

        Ok(Some(Self {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 32_768,
            sandbox_network: file.sandbox.network,
            fs_read_deny: file.fs.read_deny.unwrap_or_else(default_read_deny),
            fs_protected: file.fs.protected.unwrap_or_else(default_protected),
            redact_tool_output: file.redaction.tool_output,
            rules,
            hooks,
        }))
    }
}

/// The config file as written.
///
/// `deny_unknown_fields` on every level is the point of #26: a key the loader
/// does not implement is an error, not a setting that quietly does nothing.
/// That includes the PLAN 6.8 keys that are still unimplemented, which is
/// deliberate - a config written for a future schema should fail loudly rather
/// than half-apply.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    sandbox: SandboxSection,
    fs: FsSection,
    redaction: RedactionSection,
    /// `[[rule]]` entries.
    #[serde(rename = "rule")]
    rule: Vec<RuleSection>,
    hooks: HooksSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct SandboxSection {
    network: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FsSection {
    /// `None` means "not configured", so the credential defaults apply; `[]`
    /// means the user opted out of them.
    read_deny: Option<Vec<String>>,
    protected: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RedactionSection {
    tool_output: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSection {
    id: String,
    #[serde(rename = "match")]
    pattern: String,
    decision: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct HooksSection {
    #[serde(rename = "PreToolUse")]
    pre_tool_use: Vec<HookSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookSection {
    matcher: String,
    command: Vec<String>,
    #[serde(default = "default_hook_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    fail_closed: bool,
}

fn default_hook_timeout() -> u64 {
    10
}
