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
///
/// `history` outlives a single turn: the M2 REPL and BC-2.9 both need the
/// next request to carry what happened in the previous one (notably the
/// "interrupted by user" tool result of a cancelled command). The system
/// prompt is not stored; it is prepended to every request.
pub struct Agent {
    pub(crate) cfg: Config,
    provider: Arc<dyn Provider>,
    pub(crate) approver: Arc<dyn Approver>,
    history: Vec<Message>,
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
            history: Vec::new(),
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
        self.history.push(Message::User {
            content: user_input.to_string(),
        });

        let tools = tool_specs(); // read, write, edit, bash, agent

        for _turn in 0..self.cfg.max_turns {
            events
                .send(Event::TurnStarted)
                .await
                .map_err(|_| CoreError::ChannelClosed)?;

            let mut messages = Vec::with_capacity(self.history.len() + 1);
            messages.push(Message::System {
                content: system_prompt(),
            });
            messages.extend(self.history.iter().cloned());

            let req = LlmRequest {
                messages,
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
                        self.history.push(message.clone());

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
                                    // Once a cancel lands, the remaining calls are not
                                    // executed, but each still gets a Tool message: the
                                    // model rejects a reply whose call ids are not all
                                    // answered, so the history must stay well formed.
                                    if cancel.is_cancelled() {
                                        events
                                            .send(Event::ToolFinished {
                                                id: call.id.clone(),
                                                ok: false,
                                                display: "interrupted by user".to_string(),
                                            })
                                            .await
                                            .map_err(|_| CoreError::ChannelClosed)?;
                                        self.history.push(Message::Tool {
                                            tool_call_id: call.id.clone(),
                                            content: "interrupted by user".to_string(),
                                            ok: false,
                                        });
                                        continue;
                                    }

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
                                        execute_tool(call, &self.cfg, &self.approver, &cancel)
                                            .await?;

                                    events
                                        .send(Event::ToolFinished {
                                            id: call.id.clone(),
                                            ok: result.ok,
                                            display: result.display,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;

                                    self.history.push(Message::Tool {
                                        tool_call_id: call.id.clone(),
                                        content: result.content,
                                        ok: result.ok,
                                    });
                                }

                                if cancel.is_cancelled() {
                                    events
                                        .send(Event::TurnFinished {
                                            stop: StopReason::Aborted,
                                            usage: None,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;
                                    return Ok(StopReason::Aborted);
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

        // PLAN 5: the limit is a normal stop with a notice, not an error.
        // The CLI turns this notice into exit code 3 (BC-2.10).
        events
            .send(Event::Notice("turn limit reached".to_string()))
            .await
            .map_err(|_| CoreError::ChannelClosed)?;
        events
            .send(Event::TurnFinished {
                stop: StopReason::Stop,
                usage: None,
            })
            .await
            .map_err(|_| CoreError::ChannelClosed)?;
        Ok(StopReason::Stop)
    }

    pub fn session_path(&self) -> &Path {
        Path::new("")
    }
}
