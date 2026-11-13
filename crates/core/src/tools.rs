//! Tool specs advertised to the model, and the executors behind them.

use std::sync::Arc;
use std::time::Duration;

use barry_protocol::{ToolCall, ToolSpec};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::context::truncate;
use crate::{Approver, CoreError};

/// The result of one tool call, before it becomes a [`barry_protocol::Message::Tool`].
pub(crate) struct ToolResult {
    pub(crate) ok: bool,
    pub(crate) content: String,
    pub(crate) display: String,
}

impl ToolResult {
    /// The result recorded for a call that was cut short by cancellation.
    pub(crate) fn interrupted() -> Self {
        Self {
            ok: false,
            content: "interrupted by user".to_string(),
            display: "interrupted by user".to_string(),
        }
    }

    /// Turns a tool error into a result for the model. PLAN 5: panics and
    /// errors inside a tool never abort the turn, they become ok:false.
    pub(crate) fn internal_error(err: &CoreError) -> Self {
        Self {
            ok: false,
            content: format!("internal tool error: {err}"),
            display: "internal tool error".to_string(),
        }
    }
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
        ToolSpec {
            name: "agent".to_string(),
            description: "Run a sub-agent on a task and return its final answer".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "The task for the sub-agent"
                    },
                    "allow_writes": {
                        "type": "boolean",
                        "description": "Allow the sub-agent to write files (default false)"
                    }
                },
                "required": ["task"]
            }),
        },
    ]
}

pub(crate) async fn execute_tool(
    call: &ToolCall,
    cfg: &Config,
    _approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
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
            execute_bash(command, timeout_secs, cancel).await
        }
        // Advertised (PLAN 5.1, BC-2.11) so the model can see the interface,
        // but sub-agents arrive in M8 (PLAN 6.6). Say so plainly instead of
        // letting it look like a typo.
        "agent" => Ok(ToolResult {
            ok: false,
            content: "sub-agents are not available yet: the agent tool arrives in M8".to_string(),
            display: "agent unavailable".to_string(),
        }),
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

/// Sends SIGKILL to a whole process group. The child is spawned with
/// `process_group(0)`, so `-<pid>` reaches the shell and everything it started.
fn kill_process_group(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(format!("-{pid}"))
        .output();
}

async fn execute_bash(
    command: &str,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .process_group(0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CoreError::Provider(format!("failed to run /bin/sh: {e}")))?;

    let child_id = child.id().unwrap_or(0);

    // `wait_with_output` consumes the child, so it moves into the racing future.
    // Once that future is dropped (cancel arm) the only handle left is the pid,
    // which is why the group is killed by pid rather than via `child.kill()`.
    let wait = async move { child.wait_with_output().await };

    tokio::select! {
        biased;
        () = cancel.cancelled() => {
            kill_process_group(child_id);
            Ok(ToolResult::interrupted())
        }
        result = tokio::time::timeout(Duration::from_secs(timeout_secs), wait) => {
            match result {
                Ok(Ok(output)) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    // Bind the Cow temporaries: `truncate` borrows from them, so they
                    // must outlive the returned Cow.
                    let stdout_raw = String::from_utf8_lossy(&output.stdout);
                    let stderr_raw = String::from_utf8_lossy(&output.stderr);
                    let stdout = truncate(&stdout_raw, 30_000);
                    let stderr = truncate(&stderr_raw, 30_000);

                    // PLAN 5.1: exit_code, stdout and stderr on both paths,
                    // each stream truncated on its own.
                    let content =
                        format!("exit_code: {exit_code}\nstdout: {stdout}\nstderr: {stderr}");
                    Ok(ToolResult {
                        ok: exit_code == 0,
                        content,
                        display: format!("bash exit {exit_code}"),
                    })
                }
                Ok(Err(io_err)) => Err(CoreError::Provider(format!(
                    "failed to read bash output: {io_err}"
                ))),
                Err(_elapsed) => {
                    kill_process_group(child_id);
                    Ok(ToolResult {
                        ok: false,
                        content: format!("timed out after {timeout_secs}s"),
                        display: format!("bash timed out after {timeout_secs}s"),
                    })
                }
            }
        }
    }
}
