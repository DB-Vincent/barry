//! Core agent loop for barry.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::context::truncate;
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{
    ApprovalChoice, ApprovalRequest, Event, Message, StopReason, ToolCall, ToolSpec,
};
use futures::channel::mpsc;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde_json::json;
use tokio_util::sync::CancellationToken;

pub mod config;
pub mod context;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors from the core agent.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("config error: {0}")]
    Config(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("event channel closed")]
    ChannelClosed,
}

/// An approval decision callback.
pub trait Approver: Send + Sync {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice>;
}

/// The main agent that drives the turn loop.
pub struct Agent {
    cfg: crate::config::Config,
    provider: Arc<dyn Provider>,
    approver: Arc<dyn Approver>,
}

fn system_prompt() -> String {
    "You are a helpful coding agent. You have access to tools: read, write, edit, bash, agent."
        .to_string()
}

fn tool_specs() -> Vec<ToolSpec> {
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

struct ToolResult {
    ok: bool,
    content: String,
    display: String,
}

impl Agent {
    pub fn new(
        cfg: crate::config::Config,
        provider: Arc<dyn Provider>,
        approver: Arc<dyn Approver>,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            cfg,
            provider,
            approver,
        })
    }

    pub fn resume(
        _cfg: crate::config::Config,
        _provider: Arc<dyn Provider>,
        _approver: Arc<dyn Approver>,
        _session_file: &Path,
    ) -> Result<Self, CoreError> {
        Err(CoreError::NotImplemented(
            "Agent::resume not yet implemented".into(),
        ))
    }

    pub async fn run_turn(
        &mut self,
        user_input: &str,
        mut events: mpsc::Sender<Event>,
        cancel: CancellationToken,
    ) -> Result<StopReason, CoreError> {
        let mut messages = vec![
            Message::System {
                content: system_prompt(),
            },
            Message::User {
                content: user_input.to_string(),
            },
        ];

        let tools = tool_specs(); // read, write, edit, bash, agent

        for _turn in 0..self.cfg.max_turns {
            events
                .send(Event::TurnStarted)
                .await
                .map_err(|_| CoreError::ChannelClosed)?;

            let req = LlmRequest {
                messages: messages.clone(),
                tools: tools.clone(),
            };
            let mut stream = self.provider.stream(req, cancel.clone());

            while let Some(event) = stream.next().await {
                let event = event.map_err(|e| CoreError::Provider(e.to_string()))?;

                match event {
                    LlmEvent::TextDelta(s) => {
                        events
                            .send(Event::TextDelta(s))
                            .await
                            .map_err(|_| CoreError::ChannelClosed)?;
                    }
                    LlmEvent::ReasoningDelta(s) => {
                        events
                            .send(Event::ReasoningDelta(s))
                            .await
                            .map_err(|_| CoreError::ChannelClosed)?;
                    }
                    LlmEvent::Done { message, stop, .. } => {
                        messages.push(message.clone());

                        match stop {
                            StopReason::Stop => {
                                events
                                    .send(Event::TurnFinished { stop, usage: None })
                                    .await
                                    .map_err(|_| CoreError::ChannelClosed)?;
                                return Ok(StopReason::Stop);
                            }
                            StopReason::ToolCalls => {
                                let tool_calls = match &message {
                                    Message::Assistant { tool_calls, .. } => tool_calls.clone(),
                                    _ => Vec::new(),
                                };
                                for call in &tool_calls {
                                    let display = format!("{} {}", call.name, call.arguments);
                                    events
                                        .send(Event::ToolStarted {
                                            id: call.id.clone(),
                                            name: call.name.clone(),
                                            display,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;

                                    let result =
                                        Self::execute_tool(call, &self.cfg, &self.approver).await?;

                                    events
                                        .send(Event::ToolFinished {
                                            id: call.id.clone(),
                                            ok: result.ok,
                                            display: result.display,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;

                                    messages.push(Message::Tool {
                                        tool_call_id: call.id.clone(),
                                        content: result.content,
                                        ok: result.ok,
                                    });
                                }
                                // loop continues: call LLM again with tool results
                            }
                            StopReason::Aborted => {
                                events
                                    .send(Event::TurnFinished { stop, usage: None })
                                    .await
                                    .map_err(|_| CoreError::ChannelClosed)?;
                                return Ok(StopReason::Aborted);
                            }
                            _ => return Err(CoreError::Provider("unexpected stop reason".into())),
                        }
                    }
                }

                if cancel.is_cancelled() {
                    return Ok(StopReason::Aborted);
                }
            }
        }

        Err(CoreError::Provider("max turns exceeded".into()))
    }

    pub fn session_path(&self) -> &Path {
        Path::new("")
    }

    async fn execute_tool(
        call: &ToolCall,
        _cfg: &crate::config::Config,
        _approver: &Arc<dyn Approver>,
    ) -> Result<ToolResult, CoreError> {
        match call.name.as_str() {
            "read" => {
                let path = call
                    .arguments
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                Self::execute_read(path, &call.id, _approver).await
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
                Self::execute_write(path, content).await
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
                Self::execute_edit(path, old_string, new_string).await
            }
            "bash" => {
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
                Self::execute_bash(command, timeout_secs).await
            }
            _ => Ok(ToolResult {
                ok: false,
                content: format!("unknown tool: {}", call.name),
                display: format!("unknown tool: {}", call.name),
            }),
        }
    }

    async fn execute_read(
        path: &str,
        _call_id: &str,
        _approver: &Arc<dyn Approver>,
    ) -> Result<ToolResult, CoreError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
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
        let content =
            std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
        let count = content.matches(old_string).count();

        match count {
            0 => Ok(ToolResult {
                ok: false,
                content: format!("no matches found for '{}' in {}", old_string, path),
                display: format!("no matches found for '{}'", old_string),
            }),
            1 => {
                let new_content = content.replacen(old_string, new_string, 1);
                std::fs::write(path, &new_content)
                    .map_err(|e| CoreError::Provider(e.to_string()))?;
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
}
