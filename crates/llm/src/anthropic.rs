//! Anthropic Messages API provider.
//!
//! Sends `POST {base_url}/v1/messages` with `stream: true` and converts the
//! SSE response into [`LlmEvent`]s. The bearer token comes from a
//! [`TokenSource`]; the default asks the official `ant` CLI for the OAuth
//! profile's access token on every request, so Barry never stores or
//! refreshes credentials itself.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use barry_protocol::{Message, StopReason, ToolCall, ToolSpec, Usage};
use futures::SinkExt;
use futures::channel::mpsc;
use futures::stream::{BoxStream, StreamExt};
use reqwest::{Client, Url};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::retry::send_with_retry;
use crate::sse::{SseEvent, SseParser, parse_event_block};
use crate::{LlmError, LlmEvent, LlmRequest, Provider};

/// Value of the `anthropic-version` header.
const API_VERSION: &str = "2026-10-21";
/// Time allowed to establish the TCP/TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum silence between two body chunks.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Time allowed for `ant` to print a token.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Most content blocks accepted in one response.
const MAX_BLOCKS: u64 = 256;

/// Where the bearer token comes from.
#[derive(Clone)]
#[non_exhaustive]
pub enum TokenSource {
    /// Run `ant auth print-credentials --access-token --profile <profile>`.
    /// The CLI refreshes an expired token before printing it.
    AntCli { profile: String },
    /// A fixed token. For tests only; never built from user configuration.
    Static(String),
}

impl TokenSource {
    async fn fetch(&self) -> Result<String, LlmError> {
        match self {
            Self::Static(token) => Ok(token.clone()),
            Self::AntCli { profile } => {
                let mut command = tokio::process::Command::new("ant");
                command
                    .args(["auth", "print-credentials", "--access-token", "--profile"])
                    .arg(profile)
                    // Same scrubbing as `barry auth`: these variables would
                    // shadow the selected OAuth profile.
                    .env_remove("ANTHROPIC_API_KEY")
                    .env_remove("ANTHROPIC_AUTH_TOKEN")
                    .env_remove("ANTHROPIC_PROFILE")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true);
                let output = tokio::time::timeout(TOKEN_TIMEOUT, command.output())
                    .await
                    .map_err(|_| LlmError::Credentials)?
                    .map_err(|_| LlmError::Credentials)?;
                if !output.status.success() {
                    return Err(LlmError::Credentials);
                }
                let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if token.is_empty() {
                    return Err(LlmError::Credentials);
                }
                Ok(token)
            }
        }
    }
}

/// An Anthropic Messages API provider.
#[derive(Clone)]
pub struct AnthropicProvider {
    model: String,
    base_url: Url,
    max_output_tokens: u64,
    token_source: TokenSource,
    client: Client,
}

impl AnthropicProvider {
    /// Create a new provider.
    /// - `base_url`: e.g. `https://api.anthropic.com`
    /// - `max_output_tokens`: value of `max_tokens` in the request body
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be built (for example when the TLS
    /// backend fails to initialise).
    #[must_use]
    pub fn new(
        model: String,
        base_url: Url,
        max_output_tokens: u64,
        token_source: TokenSource,
    ) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "builder only fails on TLS backend init, a startup invariant"
        )]
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");
        Self {
            model,
            base_url,
            max_output_tokens,
            token_source,
            client,
        }
    }
}

impl Provider for AnthropicProvider {
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
                let _ = error_tx.send(Err(e)).await;
            }
        });

        Box::pin(rx)
    }
}

async fn run_stream(
    provider: AnthropicProvider,
    req: LlmRequest,
    cancel: CancellationToken,
    mut tx: mpsc::Sender<Result<LlmEvent, LlmError>>,
) -> Result<(), LlmError> {
    let url = messages_url(&provider.base_url)?;
    let token = provider.token_source.fetch().await?;

    let (system, messages) = build_messages(&req.messages);
    let mut body = json!({
        "model": provider.model,
        "max_tokens": provider.max_output_tokens,
        "messages": messages,
        "stream": true,
    });
    if !system.is_empty() {
        body["system"] = Value::String(system);
    }
    if !req.tools.is_empty() {
        body["tools"] = Value::Array(build_tools(&req.tools));
    }

    let request = provider
        .client
        .post(url)
        .header("anthropic-version", API_VERSION)
        // `bearer_auth` marks the header sensitive so it is not debug-printed.
        .bearer_auth(token)
        .json(&body);

    let response = send_with_retry(&provider.client, request).await?;
    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        tx.send(Err(LlmError::Auth {
            provider: "anthropic".to_string(),
        }))
        .await
        .map_err(|_| LlmError::Cancelled)?;
        return Ok(());
    }
    if !status.is_success() {
        // Never include the response body.
        tx.send(Err(LlmError::UnexpectedStatus {
            status: status.as_u16(),
        }))
        .await
        .map_err(|_| LlmError::Cancelled)?;
        return Ok(());
    }

    let mut byte_stream = response.bytes_stream();
    let mut parser = SseParser::new();
    let mut state = AnthropicState::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                send_event(&mut tx, state.finish(Some(StopReason::Aborted))).await?;
                return Ok(());
            }
            chunk = tokio::time::timeout(IDLE_TIMEOUT, byte_stream.next()) => {
                match chunk {
                    Err(_) => {
                        let stop = StopReason::Error("idle read timeout".to_string());
                        send_event(&mut tx, state.finish(Some(stop))).await?;
                        return Ok(());
                    }
                    Ok(Some(Err(e))) => {
                        tx.send(Err(LlmError::Stream(e)))
                            .await
                            .map_err(|_| LlmError::Cancelled)?;
                        return Ok(());
                    }
                    Ok(Some(Ok(bytes))) => {
                        let blocks = parser.feed(&bytes);
                        if process_blocks(&blocks, &mut state, &mut tx).await? {
                            send_event(&mut tx, state.finish(None)).await?;
                            return Ok(());
                        }
                    }
                    Ok(None) => {
                        let blocks = parser.flush();
                        process_blocks(&blocks, &mut state, &mut tx).await?;
                        send_event(&mut tx, state.finish(None)).await?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Feed parsed blocks into the state. Returns `true` once the message ended.
async fn process_blocks(
    blocks: &[String],
    state: &mut AnthropicState,
    tx: &mut mpsc::Sender<Result<LlmEvent, LlmError>>,
) -> Result<bool, LlmError> {
    for block in blocks {
        match parse_event_block(block) {
            Some(SseEvent::Data(payload)) => {
                for event in state.handle(&payload) {
                    send_event(tx, event).await?;
                }
                if state.ended {
                    return Ok(true);
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

/// Join `v1/messages` without dropping a path prefix from the base URL.
pub(crate) fn messages_url(base_url: &Url) -> Result<Url, LlmError> {
    let mut base = base_url.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    Ok(base.join("v1/messages")?)
}

/// Map protocol messages to the Messages API: system text is a top-level
/// field, tool results are `tool_result` blocks inside a user message.
pub(crate) fn build_messages(messages: &[Message]) -> (String, Vec<Value>) {
    let mut system: Vec<&str> = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    // Whether the last entry of `out` is a user message made only of
    // tool results, so consecutive results can share one message.
    let mut last_is_tool_results = false;

    for message in messages {
        match message {
            Message::System { content } => system.push(content),
            Message::User { content } => {
                out.push(json!({ "role": "user", "content": content }));
                last_is_tool_results = false;
            }
            Message::Assistant {
                content,
                tool_calls,
                ..
            } => {
                let mut blocks: Vec<Value> = Vec::new();
                if let Some(text) = content
                    && !text.is_empty()
                {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
                for call in tool_calls {
                    // Invalid JSON arguments are kept as a string upstream;
                    // the API requires an object.
                    let input = if call.arguments.is_object() {
                        call.arguments.clone()
                    } else {
                        json!({})
                    };
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": input,
                    }));
                }
                if blocks.is_empty() {
                    // The API rejects an empty assistant turn.
                    blocks.push(json!({ "type": "text", "text": "(no content)" }));
                }
                out.push(json!({ "role": "assistant", "content": blocks }));
                last_is_tool_results = false;
            }
            Message::Tool {
                tool_call_id,
                content,
                ok,
            } => {
                let block = json!({
                    "type": "tool_result",
                    "tool_use_id": tool_call_id,
                    "content": content,
                    "is_error": !ok,
                });
                if last_is_tool_results
                    && let Some(Value::Array(blocks)) =
                        out.last_mut().and_then(|m| m.get_mut("content"))
                {
                    blocks.push(block);
                } else {
                    out.push(json!({ "role": "user", "content": [block] }));
                    last_is_tool_results = true;
                }
            }
        }
    }
    (system.join("\n\n"), out)
}

fn build_tools(tools: &[ToolSpec]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters,
            })
        })
        .collect()
}

/// A content block being assembled from stream events.
enum Block {
    Text,
    Thinking,
    ToolUse {
        id: String,
        name: String,
        arguments: String,
    },
}

/// Folds Messages API stream events into deltas and one final message.
pub(crate) struct AnthropicState {
    text: String,
    reasoning: String,
    blocks: BTreeMap<u64, Block>,
    stop: Option<StopReason>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    error: Option<String>,
    pub(crate) ended: bool,
}

impl AnthropicState {
    pub(crate) fn new() -> Self {
        Self {
            text: String::new(),
            reasoning: String::new(),
            blocks: BTreeMap::new(),
            stop: None,
            input_tokens: None,
            output_tokens: None,
            error: None,
            ended: false,
        }
    }

    /// Handle one `data:` payload, returning any deltas it carries.
    pub(crate) fn handle(&mut self, chunk: &Value) -> Vec<LlmEvent> {
        let mut events = Vec::new();
        match chunk.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if let Some(usage) = chunk.pointer("/message/usage") {
                    self.read_usage(usage);
                }
            }
            Some("content_block_start") => self.block_start(chunk),
            Some("content_block_delta") => self.block_delta(chunk, &mut events),
            Some("message_delta") => {
                if let Some(reason) = chunk.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.stop = Some(map_stop_reason(reason));
                }
                if let Some(usage) = chunk.get("usage") {
                    self.read_usage(usage);
                }
            }
            Some("message_stop") => self.ended = true,
            Some("error") => {
                // Keep only the error type; the message text is not trusted.
                let kind = chunk
                    .pointer("/error/type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                self.error = Some(format!("provider stream error: {kind}"));
                self.ended = true;
            }
            _ => {}
        }
        events
    }

    fn read_usage(&mut self, usage: &Value) {
        let field = |name: &str| usage.get(name).and_then(Value::as_u64);
        // Cached prompt tokens are reported separately; count them as input.
        let input = field("input_tokens").map(|n| {
            n + field("cache_creation_input_tokens").unwrap_or(0)
                + field("cache_read_input_tokens").unwrap_or(0)
        });
        if input.is_some() {
            self.input_tokens = input;
        }
        if let Some(output) = field("output_tokens") {
            self.output_tokens = Some(output);
        }
    }

    fn block_start(&mut self, chunk: &Value) {
        let Some(index) = chunk.get("index").and_then(Value::as_u64) else {
            return;
        };
        if index >= MAX_BLOCKS {
            return;
        }
        let Some(block) = chunk.get("content_block") else {
            return;
        };
        let kind = block.get("type").and_then(Value::as_str);
        let entry = match kind {
            Some("text") => Block::Text,
            Some("thinking" | "redacted_thinking") => Block::Thinking,
            Some("tool_use") => Block::ToolUse {
                id: block
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: block
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: String::new(),
            },
            _ => return,
        };
        self.blocks.insert(index, entry);
    }

    fn block_delta(&mut self, chunk: &Value, events: &mut Vec<LlmEvent>) {
        let Some(delta) = chunk.get("delta") else {
            return;
        };
        let index = chunk.get("index").and_then(Value::as_u64).unwrap_or(0);
        match delta.get("type").and_then(Value::as_str) {
            Some("text_delta") => {
                if let Some(text) = delta.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    self.text.push_str(text);
                    events.push(LlmEvent::TextDelta(text.to_string()));
                }
            }
            Some("thinking_delta") => {
                if let Some(text) = delta.get("thinking").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    self.reasoning.push_str(text);
                    events.push(LlmEvent::ReasoningDelta(text.to_string()));
                }
            }
            Some("input_json_delta") => {
                if let Some(partial) = delta.get("partial_json").and_then(Value::as_str)
                    && let Some(Block::ToolUse { arguments, .. }) = self.blocks.get_mut(&index)
                {
                    arguments.push_str(partial);
                }
            }
            _ => {}
        }
    }

    /// Consume the state and produce the single terminal `Done` event.
    /// `forced` overrides the server's stop reason (cancellation, timeout...).
    pub(crate) fn finish(self, forced: Option<StopReason>) -> LlmEvent {
        let tool_calls: Vec<ToolCall> = self
            .blocks
            .into_values()
            .filter_map(|block| match block {
                Block::ToolUse {
                    id,
                    name,
                    arguments,
                } if !id.is_empty() && !name.is_empty() => {
                    // A tool without parameters streams no JSON at all.
                    let arguments = if arguments.is_empty() {
                        json!({})
                    } else {
                        serde_json::from_str(&arguments).unwrap_or(Value::String(arguments))
                    };
                    Some(ToolCall {
                        id,
                        name,
                        arguments,
                    })
                }
                _ => None,
            })
            .collect();

        let error = self.error.map(StopReason::Error);
        let mut stop = forced.or(error).or(self.stop).unwrap_or(StopReason::Stop);
        if stop == StopReason::Stop && !tool_calls.is_empty() {
            stop = StopReason::ToolCalls;
        }

        let usage = match (self.input_tokens, self.output_tokens) {
            (None, None) => None,
            (input, output) => Some(Usage {
                input_tokens: input.unwrap_or(0),
                output_tokens: output.unwrap_or(0),
            }),
        };

        LlmEvent::Done {
            message: Message::Assistant {
                content: (!self.text.is_empty()).then_some(self.text),
                reasoning: (!self.reasoning.is_empty()).then_some(self.reasoning),
                tool_calls,
            },
            stop,
            usage,
        }
    }
}

pub(crate) fn map_stop_reason(reason: &str) -> StopReason {
    match reason {
        "max_tokens" | "model_context_window_exceeded" => StopReason::Length,
        "tool_use" => StopReason::ToolCalls,
        "refusal" => StopReason::ContentFilter,
        // end_turn, stop_sequence, pause_turn and anything new.
        _ => StopReason::Stop,
    }
}
