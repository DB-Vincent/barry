//! LLM client for barry.
//! Provider trait and shared request/event types.

#![forbid(unsafe_code)]

use barry_protocol::{Message, StopReason, ToolSpec, Usage};
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
    /// The HTTP request could not be built or sent.
    #[error("transport error: {0}")]
    Http(#[from] reqwest::Error),
    /// The endpoint URL could not be joined with the request path.
    #[error("transport error: invalid endpoint URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// The server answered with a non-success status. The body is dropped on
    /// purpose: it may echo the API key.
    #[error("transport error: unexpected status: {status}")]
    UnexpectedStatus { status: u16 },
    /// The response body failed while streaming.
    #[error("stream error: {0}")]
    Stream(#[source] reqwest::Error),
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

/// Provider quirks that differ between OpenAI-compatible servers.
#[derive(Debug, Clone, Default)]
pub struct Compat {
    /// The field name used for reasoning deltas: "reasoning_content" | "reasoning"
    pub reasoning_field: Option<String>,
    /// Whether the provider supports parallel tool calls
    pub supports_parallel_tool_calls: bool,
    /// Whether the provider sends usage in stream chunks
    pub supports_stream_usage: bool,
}

pub mod openai;
mod retry;
mod sse;

pub use openai::OpenAiProvider;

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
