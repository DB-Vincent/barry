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

        let _value: toml::Value = content.parse().map_err(|source| ConfigError::Toml {
            path: path.display().to_string(),
            source,
        })?;

        Ok(Some(Config {
            default_model: "local".to_string(),
            max_turns: 50,
        }))
    }
}
