//! OpenAI-compatible chat completions provider.
//!
//! Sends `POST {base_url}/chat/completions` with `stream: true` and converts
//! the SSE response into [`LlmEvent`]s. SSE parsing lives in [`crate::sse`],
//! retry policy in [`crate::retry`].

use std::time::Duration;

use barry_protocol::{Message, StopReason, ToolSpec};
use futures::channel::mpsc;
use futures::stream::{BoxStream, StreamExt};
use futures::SinkExt;
use reqwest::{Client, Url};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::retry::send_with_retry;
use crate::sse::{parse_event_block, SseEvent, SseParser, StreamState};
use crate::{Compat, LlmError, LlmEvent, LlmRequest, Provider};

/// Time allowed to establish the TCP/TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum silence between two body chunks. Streams are otherwise unbounded.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// An OpenAI-compatible chat completions provider.
#[derive(Clone)]
pub struct OpenAiProvider {
    model: String,
    base_url: Url,
    api_key_env: Option<String>,
    max_output_tokens: u64,
    compat: Compat,
    client: Client,
}

impl OpenAiProvider {
    /// Create a new provider.
    /// - `model`: model id sent in the request body
    /// - `base_url`: e.g. `http://localhost:11434/v1`
    /// - `api_key_env`: name of the env var holding the key, or `None`
    /// - `max_output_tokens`: value of `max_tokens` in the request body
    /// - `compat`: provider quirks (reasoning field, parallel tools, stream usage)
    pub fn new(
        model: String,
        base_url: Url,
        api_key_env: Option<String>,
        max_output_tokens: u64,
        compat: Compat,
    ) -> Self {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");
        Self {
            model,
            base_url,
            api_key_env,
            max_output_tokens,
            compat,
            client,
        }
    }
}

impl Provider for OpenAiProvider {
    fn stream(
        &self,
        req: LlmRequest,
        cancel: CancellationToken,
    ) -> BoxStream<'static, Result<LlmEvent, LlmError>> {
        let (tx, rx) = mpsc::channel(32);
        let provider = self.clone();
        let mut error_tx = tx.clone();

        tokio::spawn(async move {
            if let Err(e) = run_stream(provider, req, cancel, tx).await {
                // The receiver may already be gone; that is fine.
                let _ = error_tx.send(Err(e)).await;
            }
        });

        Box::pin(rx)
    }
}

/// Build the wire request, stream the body and forward events through `tx`.
async fn run_stream(
    provider: OpenAiProvider,
    req: LlmRequest,
    cancel: CancellationToken,
    mut tx: mpsc::Sender<Result<LlmEvent, LlmError>>,
) -> Result<(), LlmError> {
    let url = chat_completions_url(&provider.base_url)?;

    let mut body = json!({
        "model": provider.model,
        "messages": build_messages(&req.messages),
        "tools": build_tools(&req.tools),
        "stream": true,
        "max_tokens": provider.max_output_tokens,
    });
    if provider.compat.supports_stream_usage {
        body["stream_options"] = json!({ "include_usage": true });
    }

    let mut request = provider.client.post(url).json(&body);

    // Read the key at request time; never store it in the provider.
    if let Some(env_name) = &provider.api_key_env {
        if let Ok(key) = std::env::var(env_name) {
            if !key.is_empty() {
                request = request.bearer_auth(key);
            }
        }
    }

    let response = send_with_retry(&provider.client, request).await?;
    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        tx.send(Err(LlmError::Auth {
            provider: "openai".to_string(),
        }))
        .await
        .map_err(|_| LlmError::Cancelled)?;
        return Ok(());
    }

    if !status.is_success() {
        // Never include the response body: it may echo the key.
        tx.send(Err(LlmError::Transport {
            message: format!("unexpected status: {status}"),
        }))
        .await
        .map_err(|_| LlmError::Cancelled)?;
        return Ok(());
    }

    let mut byte_stream = response.bytes_stream();
    let mut parser = SseParser::new();
    let mut state = StreamState::new();
    let reasoning_field = provider.compat.reasoning_field.as_deref();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                send_event(&mut tx, state.finish(Some(StopReason::Aborted))).await?;
                return Ok(());
            }
            chunk = tokio::time::timeout(IDLE_TIMEOUT, byte_stream.next()) => {
                match chunk {
                    // Idle for too long: keep the partial text.
                    Err(_) => {
                        let stop = StopReason::Error("idle read timeout".to_string());
                        send_event(&mut tx, state.finish(Some(stop))).await?;
                        return Ok(());
                    }
                    Ok(Some(Err(e))) => {
                        tx.send(Err(LlmError::Stream {
                            message: e.to_string(),
                        }))
                        .await
                        .map_err(|_| LlmError::Cancelled)?;
                        return Ok(());
                    }
                    Ok(Some(Ok(bytes))) => {
                        let blocks = parser.feed(&bytes);
                        if process_blocks(&blocks, &mut state, reasoning_field, &mut tx).await? {
                            send_event(&mut tx, state.finish(None)).await?;
                            return Ok(());
                        }
                    }
                    // Connection closed without [DONE]: flush and finish normally.
                    Ok(None) => {
                        let blocks = parser.flush();
                        process_blocks(&blocks, &mut state, reasoning_field, &mut tx).await?;
                        send_event(&mut tx, state.finish(None)).await?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Feed parsed blocks into the state. Returns `true` once `[DONE]` is seen.
async fn process_blocks(
    blocks: &[String],
    state: &mut StreamState,
    reasoning_field: Option<&str>,
    tx: &mut mpsc::Sender<Result<LlmEvent, LlmError>>,
) -> Result<bool, LlmError> {
    for block in blocks {
        match parse_event_block(block) {
            Some(SseEvent::Data(payload)) => {
                for event in state.handle(&payload, reasoning_field) {
                    send_event(tx, event).await?;
                }
            }
            Some(SseEvent::Done) => return Ok(true),
            None => {}
        }
    }
    Ok(false)
}

async fn send_event(
    tx: &mut mpsc::Sender<Result<LlmEvent, LlmError>>,
    event: LlmEvent,
) -> Result<(), LlmError> {
    tx.send(Ok(event)).await.map_err(|_| LlmError::Cancelled)
}

/// Join `chat/completions` without dropping a `/v1` suffix from the base URL.
fn chat_completions_url(base_url: &Url) -> Result<Url, LlmError> {
    let mut base = base_url.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join("chat/completions")
        .map_err(|e| LlmError::Transport {
            message: e.to_string(),
        })
}

/// Map protocol messages to the OpenAI wire format.
fn build_messages(messages: &[Message]) -> Vec<Value> {
    messages
        .iter()
        .map(|message| match message {
            Message::System { content } => json!({ "role": "system", "content": content }),
            Message::User { content } => json!({ "role": "user", "content": content }),
            Message::Assistant {
                content,
                tool_calls,
                ..
            } => {
                if tool_calls.is_empty() {
                    json!({ "role": "assistant", "content": content })
                } else {
                    let tool_calls: Vec<Value> = tool_calls
                        .iter()
                        .map(|call| {
                            let arguments = serde_json::to_string(&call.arguments)
                                .unwrap_or_else(|_| "{}".to_string());
                            json!({
                                "id": call.id,
                                "type": "function",
                                "function": { "name": call.name, "arguments": arguments },
                            })
                        })
                        .collect();
                    json!({
                        "role": "assistant",
                        "content": content,
                        "tool_calls": tool_calls,
                    })
                }
            }
            Message::Tool {
                tool_call_id,
                content,
                ..
            } => json!({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": content,
            }),
        })
        .collect()
}

/// Wrap every tool spec in the `{"type":"function","function":{...}}` envelope.
fn build_tools(tools: &[ToolSpec]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            })
        })
        .collect()
}
