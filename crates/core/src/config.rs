//! Configuration loading.

use std::path::Path;

use barry_policy::BashRule;
use barry_protocol::Decision;
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

impl Default for Config {
    fn default() -> Self {
        Self {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 32_768,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
            rules: vec![],
            hooks: vec![],
        }
    }
}

impl Config {
    /// Load user config from `$BARRY_CONFIG`.
    /// Returns `Ok(None)` if `BARRY_CONFIG` is not set (defaults apply).
    pub fn load() -> Result<Option<Self>, ConfigError> {
        let Ok(path) = std::env::var("BARRY_CONFIG") else {
            return Ok(None);
        };

        let path = Path::new(&path);

        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let value: toml::Value = toml::from_str(&content).map_err(|source| ConfigError::Toml {
            path: path.display().to_string(),
            source,
        })?;

        // Extract sandbox/fs sections.
        let sandbox_network = value
            .get("sandbox")
            .and_then(|s| s.get("network"))
            .and_then(|n| n.as_bool())
            .unwrap_or(true);

        let fs_read_deny: Vec<String> = value
            .get("fs")
            .and_then(|f| f.get("read_deny"))
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let fs_protected: Vec<String> = value
            .get("fs")
            .and_then(|f| f.get("protected"))
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let rules = parse_rules(path, &value)?;

        let hooks: Vec<HookConfig> = value
            .get("hooks")
            .and_then(|h| h.get("PreToolUse"))
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let matcher = v
                            .get("matcher")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        let command: Vec<String> = v
                            .get("command")
                            .and_then(|c| c.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let timeout_secs = v
                            .get("timeout_secs")
                            .and_then(|t| t.as_integer())
                            .and_then(|t| u64::try_from(t).ok())
                            .unwrap_or(10);
                        let fail_closed = v
                            .get("fail_closed")
                            .and_then(|f| f.as_bool())
                            .unwrap_or(false);
                        if matcher.is_empty() || command.is_empty() {
                            None
                        } else {
                            Some(HookConfig {
                                matcher,
                                command,
                                timeout_secs,
                                fail_closed,
                            })
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(Self {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 32_768,
            sandbox_network,
            fs_read_deny,
            fs_protected,
            rules,
            hooks,
        }))
    }
}

/// Parse the `[[rule]]` array: `{ id, match, decision }`.
///
/// A malformed rule is a config error, not a silently skipped entry: a rule
/// the user believes is protecting them must never be dropped.
fn parse_rules(path: &Path, value: &toml::Value) -> Result<Vec<BashRule>, ConfigError> {
    let Some(entries) = value.get("rule").and_then(|r| r.as_array()) else {
        return Ok(Vec::new());
    };

    let mut rules = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let invalid = |message: String| ConfigError::Invalid {
            path: path.display().to_string(),
            message,
        };

        let id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pattern = entry
            .get("match")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() || pattern.is_empty() {
            return Err(invalid(format!(
                "rule {index}: both `id` and `match` are required"
            )));
        }

        let decision = match entry.get("decision").and_then(|v| v.as_str()) {
            Some("allow") => Decision::Allow,
            Some("deny") => Decision::Deny {
                reason: format!("rule {id} denies this command"),
            },
            Some("ask") => Decision::Ask {
                reason: format!("rule {id} requires approval"),
            },
            Some(other) => {
                return Err(invalid(format!(
                    "rule {id}: unknown decision {other:?} (expected allow, ask or deny)"
                )))
            }
            None => return Err(invalid(format!("rule {id}: `decision` is required"))),
        };

        rules.push(BashRule {
            id,
            r#match: pattern,
            decision,
        });
    }
    Ok(rules)
}
