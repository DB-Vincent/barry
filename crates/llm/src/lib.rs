//! LLM client for barry.
//! Provider trait and shared request/event types.

use barry_protocol::{Message, StopReason, ToolSpec, Usage};
use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// A request to the LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
}

/// An event from a streaming LLM response.
#[derive(Debug, Clone)]
pub enum LlmEvent {
    TextDelta(String),
    ReasoningDelta(String),
    Done {
        message: Message,
        stop: StopReason,
        usage: Option<Usage>,
    },
}

/// Errors from the LLM provider.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("auth error for provider {provider}")]
    Auth { provider: String },
    #[error("transport error: {message}")]
    Transport { message: String },
    #[error("stream error: {message}")]
    Stream { message: String },
    #[error("cancelled")]
    Cancelled,
}

/// A streaming LLM provider.
pub trait Provider: Send + Sync {
    fn stream(
        &self,
        req: LlmRequest,
        cancel: CancellationToken,
    ) -> BoxStream<'static, Result<LlmEvent, LlmError>>;
}

/// An open HTTP response body as a byte stream.
pub type BodyStream = BoxStream<'static, Result<Bytes, LlmError>>;

impl std::fmt::Display for LlmEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmEvent::TextDelta(s) => write!(f, "TextDelta({})", s),
            LlmEvent::ReasoningDelta(s) => write!(f, "ReasoningDelta({})", s),
            LlmEvent::Done { stop, usage, .. } => {
                write!(f, "Done{{stop={:?}, usage={:?}}}", stop, usage)
            }
        }
    }
}
