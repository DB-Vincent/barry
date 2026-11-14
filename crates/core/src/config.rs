//! Configuration loading.

use std::path::Path;

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
}

/// User configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub default_model: String,
    pub max_turns: u64,
    /// Sandbox: whether bash commands may access the network.
    pub sandbox_network: bool,
    /// Filesystem: paths whose contents must never be read (expanded `~`,
    /// canonicalised where they exist).
    pub fs_read_deny: Vec<String>,
    /// Filesystem: path components that always require approval (e.g. `.git`,
    /// `.barry`, `.env`).
    pub fs_protected: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_model: "local".to_string(),
            max_turns: 50,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
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

        Ok(Some(Self {
            default_model: "local".to_string(),
            max_turns: 50,
            sandbox_network,
            fs_read_deny,
            fs_protected,
        }))
    }
}
