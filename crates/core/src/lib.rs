//! Core agent loop for barry.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

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
    vec![ToolSpec {
        name: "read".to_string(),
        description: "Read a file and return its contents with line numbers".to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Path to the file" }
            },
            "required": ["path"]
        }),
    }]
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
        Ok(ToolResult {
            ok: true,
            content: numbered.clone(),
            display: numbered,
        })
    }
}
