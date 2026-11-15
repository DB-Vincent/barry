//! `PreToolUse` hooks (PLAN 6.5).
//!
//! Hooks run **outside** the sandbox, with the user's environment minus
//! secret variables (`*KEY*|*TOKEN*|*SECRET*`). They receive a JSON payload
//! on stdin and may return a decision on stdout.
//!
//! Exit codes:
//!   0: stdout may be empty or JSON `{decision, reason, updated_input, context}`.
//!   2: block the tool; stderr is returned to the model / as a Notice.
//!   other or timeout: warning Notice; blocks only if `fail_closed`.

use std::process::Stdio;
use std::time::Duration;

use crate::config::HookConfig;
use crate::CoreError;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// The outcome of running a hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// The hook allows the tool; policy is still checked afterwards.
    Allow,
    /// The hook denies the tool; this is a final decision.
    Deny { reason: String },
    /// The hook asks; treated as allow for now, policy still checked.
    Ask { reason: String },
    /// The hook rewrote the tool input.
    UpdatedInput { input: String },
    /// The hook exited 2: block the tool.
    Block { reason: String },
    /// The hook exited non-zero or timed out: warning only.
    Warning { reason: String },
}

/// JSON payload sent to a hook on stdin.
#[derive(Debug, Serialize)]
struct HookInput<'a> {
    event: &'a str,
    session_id: &'a str,
    cwd: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a str>,
}

/// JSON decision a hook may return on stdout.
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)] // `context` is reserved for future hook output.
struct HookOutput {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    updated_input: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

/// A compiled hook: its matcher is a regex against the tool name.
pub(crate) struct Hook {
    config: HookConfig,
    regex: regex::Regex,
}

impl Hook {
    pub(crate) fn new(config: HookConfig) -> Result<Self, CoreError> {
        let regex = regex::Regex::new(&config.matcher).map_err(|e| {
            CoreError::Config(format!("invalid hook matcher {:?}: {e}", config.matcher))
        })?;
        Ok(Self { config, regex })
    }

    /// Whether this hook matches the given tool name.
    pub(crate) fn matches(&self, tool_name: &str) -> bool {
        self.regex.is_match(tool_name)
    }

    /// Run the hook for a `PreToolUse` event.
    pub(crate) async fn run_pre_tool_use(
        &self,
        tool_name: &str,
        input: &str,
        cwd: &str,
        session_id: &str,
        cancel: &CancellationToken,
    ) -> Result<HookOutcome, CoreError> {
        let input_json = serde_json::to_string(&HookInput {
            event: "PreToolUse",
            session_id,
            cwd,
            tool: Some(tool_name),
            input: Some(input),
            result: None,
        })
        .map_err(|e| CoreError::Config(format!("failed to serialize hook input: {e}")))?;

        let mut cmd = tokio::process::Command::new(&self.config.command[0]);
        cmd.args(&self.config.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // User's environment minus secret variables.
        let env_cleaned: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os()
            .filter(|(k, _)| !is_secret_env(&k.to_string_lossy()))
            .collect();
        cmd.env_clear();
        cmd.envs(env_cleaned);

        let mut child = cmd
            .spawn()
            .map_err(|e| CoreError::Config(format!("failed to spawn hook: {e}")))?;
        {
            let mut stdin = child.stdin.take().expect("stdin open");
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(input_json.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }

        let timeout = Duration::from_secs(self.config.timeout_secs);
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => HookOutcome::Warning {
                reason: "hook cancelled".to_string(),
            },
            result = tokio::time::timeout(timeout, child.wait_with_output()) => {
                match result {
                    Ok(output) => match output {
                        Ok(output) => self.interpret_output(&output),
                        Err(e) => HookOutcome::Warning {
                            reason: format!("hook error: {e}"),
                        },
                    },
                    Err(_elapsed) => HookOutcome::Warning {
                        reason: format!(
                            "hook timed out after {}s",
                            self.config.timeout_secs
                        ),
                    },
                }
            }
        };
        Ok(outcome)
    }

    fn interpret_output(&self, output: &std::process::Output) -> HookOutcome {
        let code = output.status.code();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        match code {
            Some(0) => {
                if let Ok(decoded) = serde_json::from_str::<HookOutput>(&stdout) {
                    match decoded.decision.as_deref() {
                        Some("deny") => HookOutcome::Deny {
                            reason: decoded.reason.unwrap_or_default(),
                        },
                        Some("ask") => HookOutcome::Ask {
                            reason: decoded.reason.unwrap_or_default(),
                        },
                        Some("allow") => HookOutcome::Allow,
                        Some("updated_input") | None => {
                            if let Some(input) = decoded.updated_input {
                                HookOutcome::UpdatedInput { input }
                            } else {
                                HookOutcome::Allow
                            }
                        }
                        other => HookOutcome::Warning {
                            reason: format!("unknown hook decision {other:?}"),
                        },
                    }
                } else {
                    HookOutcome::Allow
                }
            }
            Some(2) => HookOutcome::Block {
                reason: stderr.trim().to_string(),
            },
            _ => HookOutcome::Warning {
                reason: format!("hook exited {:?}: {stderr}", code),
            },
        }
    }
}

/// Secret env var name patterns stripped before running a hook.
fn is_secret_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("KEY")
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_env_detection() {
        assert!(is_secret_env("OPENAI_API_KEY"));
        assert!(is_secret_env("GITHUB_TOKEN"));
        assert!(is_secret_env("DB_SECRET"));
        assert!(is_secret_env("ADMIN_PASSWORD"));
        assert!(!is_secret_env("PATH"));
        assert!(!is_secret_env("HOME"));
    }
}
