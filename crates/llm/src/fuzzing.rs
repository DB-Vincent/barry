//! Entry points for the cargo-fuzz targets. Not part of the public API.

use serde_json::Value;

use crate::sse::{parse_event_block, SseEvent, SseParser, StreamState};
use crate::LlmEvent;

/// Run a response body, delivered as `reads`, through the SSE parser and the
/// stream state, the way the OpenAI provider does. Returns the final event.
#[must_use]
pub fn stream_reads(reads: &[Vec<u8>], reasoning_field: Option<&str>) -> LlmEvent {
    let mut parser = SseParser::new();
    let mut state = StreamState::new();
    let mut blocks = Vec::new();
    for read in reads {
        blocks.extend(parser.feed(read));
    }
    blocks.extend(parser.flush());
    for block in blocks {
        if let Some(SseEvent::Data(chunk)) = parse_event_block(&block) {
            let _ = state.handle(&chunk, reasoning_field);
        }
    }
    state.finish(None)
}

/// Feed already parsed JSON chunks to the stream state and finish it.
#[must_use]
pub fn assemble_chunks(chunks: &[Value], reasoning_field: Option<&str>) -> LlmEvent {
    let mut state = StreamState::new();
    for chunk in chunks {
        let _ = state.handle(chunk, reasoning_field);
    }
    state.finish(None)
}
