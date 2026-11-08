//! Hand-written SSE parser for OpenAI-compatible streams.
//!
//! `SseParser` turns raw response bytes into complete event blocks.
//! `StreamState` folds those blocks into deltas and one final message.

use barry_protocol::{Message, StopReason, ToolCall, Usage};
use serde_json::Value;

use crate::LlmEvent;

/// One parsed SSE event block.
pub(crate) enum SseEvent {
    /// A JSON payload (`data: {...}`).
    Data(Value),
    /// The terminal `data: [DONE]` marker.
    Done,
}

/// Buffers raw bytes and yields complete SSE event blocks.
pub(crate) struct SseParser {
    buffer: String,
}

impl SseParser {
    pub(crate) fn new() -> Self {
        Self {
            buffer: String::new(),
        }
    }

    /// Feed raw bytes and return every complete block (separated by a blank line).
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buffer.push_str(&String::from_utf8_lossy(bytes));
        self.normalize_line_endings();

        let mut blocks = Vec::new();
        let mut start = 0;
        while let Some(pos) = self.buffer[start..].find("\n\n") {
            let end = start + pos;
            let block = &self.buffer[start..end];
            if !block.trim().is_empty() {
                blocks.push(block.to_string());
            }
            start = end + 2;
        }
        if start > 0 {
            self.buffer.drain(..start);
        }
        blocks
    }

    /// Return whatever is left when the connection closes without a trailing blank line.
    pub(crate) fn flush(&mut self) -> Vec<String> {
        self.normalize_line_endings();
        let block = std::mem::take(&mut self.buffer);
        if block.trim().is_empty() {
            Vec::new()
        } else {
            vec![block]
        }
    }

    /// SSE allows CRLF, LF and lone CR. A CR may be split across two reads,
    /// so normalise the whole buffer each feed instead of per chunk.
    fn normalize_line_endings(&mut self) {
        if self.buffer.contains('\r') {
            self.buffer = self.buffer.replace("\r\n", "\n").replace('\r', "\n");
        }
    }
}

/// Parse one event block: collect its `data:` lines and decode the payload.
pub(crate) fn parse_event_block(block: &str) -> Option<SseEvent> {
    let mut data_lines: Vec<&str> = Vec::new();
    for line in block.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            // SSE removes at most one space after the colon.
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        return None;
    }

    let data = data_lines.join("\n");
    if data.trim() == "[DONE]" {
        return Some(SseEvent::Done);
    }
    serde_json::from_str(&data).ok().map(SseEvent::Data)
}

/// A tool call assembled from fragments spread over several chunks.
#[derive(Debug, Clone, Default)]
struct ToolCallAccumulator {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ToolCallAccumulator {
    /// `None` until both the id and the name arrived.
    fn to_tool_call(&self) -> Option<ToolCall> {
        let id = self.id.clone()?;
        let name = self.name.clone()?;
        // Invalid JSON is not a provider error: keep the raw string (BC-1.5).
        let arguments = serde_json::from_str(&self.arguments)
            .unwrap_or_else(|_| Value::String(self.arguments.clone()));
        Some(ToolCall {
            id,
            name,
            arguments,
        })
    }
}

/// Folds SSE chunks into stream events and the final assistant message.
pub(crate) struct StreamState {
    text: String,
    reasoning: String,
    tool_calls: Vec<ToolCallAccumulator>,
    stop: Option<StopReason>,
    usage: Option<Usage>,
}

impl StreamState {
    pub(crate) fn new() -> Self {
        Self {
            text: String::new(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            stop: None,
            usage: None,
        }
    }

    /// Handle one `data:` payload, returning any deltas it carries.
    pub(crate) fn handle(&mut self, chunk: &Value, reasoning_field: Option<&str>) -> Vec<LlmEvent> {
        let mut events = Vec::new();

        if let Some(usage) = parse_usage(chunk) {
            self.usage = Some(usage);
        }

        // A usage-only chunk has an empty choices array.
        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            return events;
        };

        if let Some(delta) = choice.get("delta") {
            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                if !content.is_empty() {
                    self.text.push_str(content);
                    events.push(LlmEvent::TextDelta(content.to_string()));
                }
            }

            if let Some(field) = reasoning_field {
                if let Some(reasoning) = delta.get(field).and_then(Value::as_str) {
                    if !reasoning.is_empty() {
                        self.reasoning.push_str(reasoning);
                        events.push(LlmEvent::ReasoningDelta(reasoning.to_string()));
                    }
                }
            }

            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for fragment in tool_calls {
                    self.apply_tool_call_fragment(fragment);
                }
            }
        }

        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            if let Some(stop) = map_finish_reason(reason) {
                self.stop = Some(stop);
            }
        }

        events
    }

    /// Consume the state and produce the single terminal `Done` event.
    /// `forced` overrides the server's stop reason (cancellation, timeout...).
    pub(crate) fn finish(self, forced: Option<StopReason>) -> LlmEvent {
        let tool_calls: Vec<ToolCall> = self
            .tool_calls
            .iter()
            .filter_map(ToolCallAccumulator::to_tool_call)
            .collect();

        let mut stop = forced.or(self.stop).unwrap_or(StopReason::Stop);
        // Some servers say "stop" even when tool calls are present (BC-1.4).
        if stop == StopReason::Stop && !tool_calls.is_empty() {
            stop = StopReason::ToolCalls;
        }

        LlmEvent::Done {
            message: Message::Assistant {
                content: (!self.text.is_empty()).then_some(self.text),
                reasoning: (!self.reasoning.is_empty()).then_some(self.reasoning),
                tool_calls,
            },
            stop,
            usage: self.usage,
        }
    }

    fn apply_tool_call_fragment(&mut self, fragment: &Value) {
        let index = fragment.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
        while self.tool_calls.len() <= index {
            self.tool_calls.push(ToolCallAccumulator::default());
        }

        let acc = &mut self.tool_calls[index];
        if let Some(id) = fragment.get("id").and_then(Value::as_str) {
            acc.id = Some(id.to_string());
        }
        if let Some(function) = fragment.get("function") {
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                acc.name = Some(name.to_string());
            }
            if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                acc.arguments.push_str(arguments);
            }
        }
    }
}

fn map_finish_reason(reason: &str) -> Option<StopReason> {
    match reason {
        "stop" => Some(StopReason::Stop),
        "length" => Some(StopReason::Length),
        "tool_calls" => Some(StopReason::ToolCalls),
        "content_filter" => Some(StopReason::ContentFilter),
        _ => None,
    }
}

fn parse_usage(chunk: &Value) -> Option<Usage> {
    let usage = chunk.get("usage")?;
    let input_tokens = usage.get("prompt_tokens").and_then(Value::as_u64)?;
    let output_tokens = usage.get("completion_tokens").and_then(Value::as_u64)?;
    Some(Usage {
        input_tokens,
        output_tokens,
    })
}
