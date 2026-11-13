//! Tool specs advertised to the model, and the executors behind them.

use std::sync::Arc;
use std::time::Duration;

use barry_protocol::{ToolCall, ToolSpec};
use serde_json::json;

use crate::config::Config;
use crate::context::truncate;
use crate::{Approver, CoreError};

/// The result of one tool call, before it becomes a [`barry_protocol::Message::Tool`].
pub(crate) struct ToolResult {
    pub(crate) ok: bool,
    pub(crate) content: String,
    pub(crate) display: String,
}

pub(crate) fn system_prompt() -> String {
    "You are a helpful coding agent. You have access to tools: read, write, edit, bash, agent."
        .to_string()
}

pub(crate) fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "read".to_string(),
            description: "Read a file and return its contents with line numbers".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" }
                },
                "required": ["path"]
            }),
        },
        ToolSpec {
            name: "write".to_string(),
            description: "Write content to a file".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" },
                    "content": { "type": "string", "description": "Content to write" }
                },
                "required": ["path", "content"]
            }),
        },
        ToolSpec {
            name: "edit".to_string(),
            description: "Replace old_string with new_string in a file".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" },
                    "old_string": { "type": "string", "description": "Text to replace" },
                    "new_string": { "type": "string", "description": "Replacement text" }
                },
                "required": ["path", "old_string", "new_string"]
            }),
        },
        ToolSpec {
            name: "bash".to_string(),
            description: "Run a bash command".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to run"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600,
                        "description": "Timeout in seconds (default 120)"
                    }
                },
                "required": ["command"]
            }),
        },
    ]
}

pub(crate) async fn execute_tool(
    call: &ToolCall,
    cfg: &Config,
    _approver: &Arc<dyn Approver>,
) -> Result<ToolResult, CoreError> {
    match call.name.as_str() {
        "read" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_read(path).await
        }
        "write" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = call
                .arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_write(path, content).await
        }
        "edit" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let old_string = call
                .arguments
                .get("old_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_string = call
                .arguments
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_edit(path, old_string, new_string).await
        }
        "bash" => {
            // Unsandboxed bash is a development-only capability (PLAN line 617).
            // Refuse rather than omit the tool: the model should learn why the
            // call did not run instead of silently not having the tool.
            if !cfg.dev_unsafe_bash {
                return Ok(ToolResult {
                    ok: false,
                    content: "bash is disabled: rerun barry with --dev-unsafe-bash".to_string(),
                    display: "bash disabled (needs --dev-unsafe-bash)".to_string(),
                });
            }
            let command = call
                .arguments
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Resolve default and bounds at the boundary; the worker takes a
            // plain u64 and needs no Option.
            let timeout_secs = call
                .arguments
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .map(|secs| secs.clamp(1, 600))
                .unwrap_or(120);
            execute_bash(command, timeout_secs).await
        }
        _ => Ok(ToolResult {
            ok: false,
            content: format!("unknown tool: {}", call.name),
            display: format!("unknown tool: {}", call.name),
        }),
    }
}

async fn execute_read(path: &str) -> Result<ToolResult, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
    let numbered: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| format!("{}: {}", i + 1, line))
        .collect::<Vec<_>>()
        .join("\n");

    let numbered = truncate(&numbered, 30_000).into_owned();

    Ok(ToolResult {
        ok: true,
        content: numbered.clone(),
        display: numbered,
    })
}

async fn execute_write(path: &str, content: &str) -> Result<ToolResult, CoreError> {
    std::fs::write(path, content).map_err(|e| CoreError::Provider(e.to_string()))?;
    Ok(ToolResult {
        ok: true,
        content: format!("wrote {} bytes to {}", content.len(), path),
        display: format!("wrote {} bytes to {}", content.len(), path),
    })
}

async fn execute_edit(
    path: &str,
    old_string: &str,
    new_string: &str,
) -> Result<ToolResult, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
    let count = content.matches(old_string).count();

    match count {
        0 => Ok(ToolResult {
            ok: false,
            content: format!("no matches found for '{}' in {}", old_string, path),
            display: format!("no matches found for '{}'", old_string),
        }),
        1 => {
            let new_content = content.replacen(old_string, new_string, 1);
            std::fs::write(path, &new_content).map_err(|e| CoreError::Provider(e.to_string()))?;
            Ok(ToolResult {
                ok: true,
                content: format!(
                    "replaced 1 occurrence of '{}' with '{}' in {}",
                    old_string, new_string, path
                ),
                display: format!("replaced '{}' with '{}'", old_string, new_string),
            })
        }
        n => Ok(ToolResult {
            ok: false,
            content: format!(
                "found {} matches for '{}' in {}; no changes made",
                n, old_string, path
            ),
            display: format!("found {} matches for '{}'; no changes made", n, old_string),
        }),
    }
}

async fn execute_bash(command: &str, timeout_secs: u64) -> Result<ToolResult, CoreError> {
    let child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .process_group(0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CoreError::Provider(format!("failed to run /bin/sh: {e}")))?;

    let child_id = child.id().unwrap_or(0);

    let result =
        tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            let exit_code = output.status.code().unwrap_or(-1);
            // Bind the Cow temporaries: `truncate` borrows from them, so they
            // must outlive the returned Cow.
            let stdout_raw = String::from_utf8_lossy(&output.stdout);
            let stderr_raw = String::from_utf8_lossy(&output.stderr);
            let stdout = truncate(&stdout_raw, 30_000);
            let stderr = truncate(&stderr_raw, 30_000);

            if exit_code == 0 {
                Ok(ToolResult {
                    ok: true,
                    content: stdout.into_owned(),
                    display: format!("bash exit {exit_code}"),
                })
            } else {
                Ok(ToolResult {
                    ok: false,
                    content: format!("exit_code: {exit_code}\nstderr: {stderr}"),
                    display: format!("bash exit {exit_code}"),
                })
            }
        }
        Ok(Err(io_err)) => Err(CoreError::Provider(format!(
            "failed to read bash output: {io_err}"
        ))),
        Err(_elapsed) => {
            // Timeout: kill the child's process group (background children too).
            let _ = std::process::Command::new("kill")
                .arg("-KILL")
                .arg(format!("-{child_id}"))
                .output();

            Ok(ToolResult {
                ok: false,
                content: format!("timed out after {timeout_secs}s"),
                display: format!("bash timed out after {timeout_secs}s"),
            })
        }
    }
}
