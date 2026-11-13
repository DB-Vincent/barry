//! The turn loop: request, stream, dispatch tools, feed results back.

use std::path::Path;
use std::sync::Arc;

use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::tools::{execute_tool, system_prompt, tool_specs};
use crate::{Approver, CoreError};

/// The main agent that drives the turn loop.
pub struct Agent {
    pub(crate) cfg: Config,
    provider: Arc<dyn Provider>,
    pub(crate) approver: Arc<dyn Approver>,
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
                                        execute_tool(call, &self.cfg, &self.approver).await?;

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
}
