//! Configuration loading.

use std::path::Path;

use thiserror::Error;

use crate::budget::Budgets;

/// Errors from config loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config error in {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
    #[error("config error in {path}: {message}")]
    Invalid { path: String, message: String },
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
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
    /// Hooks run around tool execution (PLAN 6.5).
    pub hooks: Vec<HookConfig>,
    /// Limits for one autonomous run (`[budgets]`).
    pub budgets: Budgets,
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
            hooks: vec![],
            budgets: Budgets::default(),
        }
    }
}

/// Read an optional non-negative integer from `[budgets]`. A wrong type is an
/// error: a limit that is silently ignored would not protect anything.
fn budget_u64(
    table: Option<&toml::Value>,
    key: &str,
    path: &Path,
) -> Result<Option<u64>, ConfigError> {
    let Some(value) = table.and_then(|t| t.get(key)) else {
        return Ok(None);
    };
    value
        .as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .map(Some)
        .ok_or_else(|| ConfigError::Invalid {
            path: path.display().to_string(),
            message: format!("budgets.{key} must be a non-negative integer"),
        })
}

/// Read an optional number (float or integer) from `[budgets]`.
fn budget_f64(
    table: Option<&toml::Value>,
    key: &str,
    path: &Path,
) -> Result<Option<f64>, ConfigError> {
    let Some(value) = table.and_then(|t| t.get(key)) else {
        return Ok(None);
    };
    value
        .as_float()
        .or_else(|| value.as_integer().map(|n| n as f64))
        .map(Some)
        .ok_or_else(|| ConfigError::Invalid {
            path: path.display().to_string(),
            message: format!("budgets.{key} must be a number"),
        })
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

        let table = value.get("budgets");
        let budgets = Budgets {
            max_total_tokens: budget_u64(table, "max_total_tokens", path)?,
            max_cost_usd: budget_f64(table, "max_cost_usd", path)?,
            max_wall_secs: budget_u64(table, "max_wall_secs", path)?,
            max_bash_secs: budget_u64(table, "max_bash_secs", path)?,
            price_input_per_mtok: budget_f64(table, "price_input_per_mtok", path)?,
            price_output_per_mtok: budget_f64(table, "price_output_per_mtok", path)?,
        };
        budgets.validate().map_err(|message| ConfigError::Invalid {
            path: path.display().to_string(),
            message,
        })?;

        Ok(Some(Self {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 32_768,
            sandbox_network,
            fs_read_deny,
            fs_protected,
            hooks,
            budgets,
        }))
    }
}
