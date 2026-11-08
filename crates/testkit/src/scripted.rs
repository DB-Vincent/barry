//! Scripted LLM provider and approver for tests.

use std::collections::VecDeque;
use std::sync::Mutex;

use barry_core::{Approver, BoxFuture};
use barry_llm::{LlmError, LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Message, StopReason, ToolCall};
use futures::stream::{self, BoxStream, StreamExt};
use tokio_util::sync::CancellationToken;

/// A scripted reply for the LLM provider.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Return a tool call.
    Tool {
        name: String,
        arguments: serde_json::Value,
    },
    /// Return plain text.
    Text { content: String },
}

/// Scripted LLM provider — returns replies in order, records requests.
pub struct ScriptedProvider {
    replies: Mutex<VecDeque<Reply>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl ScriptedProvider {
    pub fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn seen_requests(&self) -> Vec<LlmRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Provider for ScriptedProvider {
    fn stream(
        &self,
        req: LlmRequest,
        _cancel: CancellationToken,
    ) -> BoxStream<'static, Result<LlmEvent, LlmError>> {
        self.requests.lock().unwrap().push(req);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("ScriptedProvider: ran out of replies");

        match reply {
            Reply::Text { content } => {
                let events = vec![
                    Ok(LlmEvent::TextDelta(content.clone())),
                    Ok(LlmEvent::Done {
                        message: Message::Assistant {
                            content: Some(content),
                            reasoning: None,
                            tool_calls: vec![],
                        },
                        stop: StopReason::Stop,
                        usage: None,
                    }),
                ];
                stream::iter(events).boxed()
            }
            Reply::Tool { name, arguments } => {
                let tool_call = ToolCall {
                    id: "call_1".to_string(),
                    name,
                    arguments,
                };
                let events = vec![Ok(LlmEvent::Done {
                    message: Message::Assistant {
                        content: None,
                        reasoning: None,
                        tool_calls: vec![tool_call],
                    },
                    stop: StopReason::ToolCalls,
                    usage: None,
                })];
                stream::iter(events).boxed()
            }
        }
    }
}

/// Scripted approver — returns choices in order, records requests.
pub struct ScriptedApprover {
    choices: Mutex<VecDeque<ApprovalChoice>>,
    asked: Mutex<Vec<ApprovalRequest>>,
}

impl ScriptedApprover {
    pub fn new(choices: Vec<ApprovalChoice>) -> Self {
        Self {
            choices: Mutex::new(choices.into()),
            asked: Mutex::new(Vec::new()),
        }
    }

    pub fn none() -> Self {
        Self {
            choices: Mutex::new(VecDeque::new()),
            asked: Mutex::new(Vec::new()),
        }
    }

    pub fn asked(&self) -> Vec<ApprovalRequest> {
        self.asked.lock().unwrap().clone()
    }
}

impl Approver for ScriptedApprover {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        self.asked.lock().unwrap().push(req.clone());
        let choice = self
            .choices
            .lock()
            .unwrap()
            .pop_front()
            .expect("ScriptedApprover: ran out of choices");
        Box::pin(async move { choice })
    }
}
