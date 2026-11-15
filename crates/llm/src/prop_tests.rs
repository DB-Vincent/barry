//! Property tests for the SSE framing parser and tool-call assembly.
//!
//! The parser sits on untrusted network input, so the first group only asserts
//! that nothing panics. The second group asserts that the result does not
//! depend on how the byte stream is split across reads, and that tool calls
//! streamed as interleaved fragments are reassembled exactly.

use barry_protocol::{Message, StopReason, ToolCall};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::fmt::Write as _;

use crate::LlmEvent;
use crate::sse::{SseEvent, SseParser, StreamState, parse_event_block};

fn json_value(text: &'static str) -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|n| json!(n)),
        text.prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 16, 4, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::vec(("[a-z]{1,4}", inner), 0..4)
                .prop_map(|pairs| Value::Object(pairs.into_iter().collect())),
        ]
    })
}

/// A tool call to stream, and the fragments its arguments are cut into.
#[derive(Debug, Clone)]
struct Planned {
    call: ToolCall,
    fragments: Vec<String>,
}

fn split_at_cuts(text: &str, cuts: &[usize]) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut points: Vec<usize> = cuts.iter().map(|c| c % (chars.len() + 1)).collect();
    points.push(0);
    points.push(chars.len());
    points.sort_unstable();
    points.dedup();
    points
        .windows(2)
        .map(|w| chars[w[0]..w[1]].iter().collect())
        .collect()
}

fn planned(text: &'static str) -> impl Strategy<Value = Planned> {
    (
        "[a-z0-9_]{1,12}",
        "[a-z_]{1,10}",
        json_value(text),
        prop::collection::vec(any::<usize>(), 0..6),
    )
        .prop_map(|(id, name, arguments, cuts)| {
            let fragments = split_at_cuts(&arguments.to_string(), &cuts);
            Planned {
                call: ToolCall {
                    id,
                    name,
                    arguments,
                },
                fragments,
            }
        })
}

/// Chunks in streaming order: per-call order is kept, calls are interleaved
/// according to `order`. The first fragment of a call carries its id and name.
fn chunks_for(plans: &[Planned], order: &[u8]) -> Vec<Value> {
    let mut next = vec![0usize; plans.len()];
    let mut chunks = Vec::new();
    let mut emit = |index: usize, next: &mut Vec<usize>| {
        let plan = &plans[index];
        let at = next[index];
        let mut function = json!({ "arguments": plan.fragments[at] });
        let mut fragment = json!({ "index": index });
        if at == 0 {
            fragment["id"] = json!(plan.call.id);
            function["name"] = json!(plan.call.name);
        }
        fragment["function"] = function;
        next[index] += 1;
        chunks.push(json!({ "choices": [{ "delta": { "tool_calls": [fragment] } }] }));
    };
    for pick in order {
        let start = usize::from(*pick) % plans.len();
        if let Some(index) = (0..plans.len())
            .map(|k| (start + k) % plans.len())
            .find(|&i| next[i] < plans[i].fragments.len())
        {
            emit(index, &mut next);
        }
    }
    for index in 0..plans.len() {
        while next[index] < plans[index].fragments.len() {
            emit(index, &mut next);
        }
    }
    chunks
}

fn finish_tool_calls(state: StreamState) -> (Vec<ToolCall>, StopReason) {
    match state.finish(None) {
        LlmEvent::Done {
            message: Message::Assistant { tool_calls, .. },
            stop,
            ..
        } => (tool_calls, stop),
        other => panic!("unexpected final event: {other:?}"),
    }
}

/// Feed `bytes` in pieces cut at `cuts`, then flush. Returns every block.
fn blocks_for(bytes: &[u8], cuts: &[usize]) -> Vec<String> {
    let mut points: Vec<usize> = cuts.iter().map(|c| c % (bytes.len() + 1)).collect();
    points.push(0);
    points.push(bytes.len());
    points.sort_unstable();
    points.dedup();
    let mut parser = SseParser::new();
    let mut blocks = Vec::new();
    for w in points.windows(2) {
        blocks.extend(parser.feed(&bytes[w[0]..w[1]]));
    }
    blocks.extend(parser.flush());
    blocks
}

proptest! {
    #[test]
    fn parser_never_panics_on_arbitrary_bytes(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..8),
    ) {
        let mut parser = SseParser::new();
        for chunk in &chunks {
            for block in parser.feed(chunk) {
                let _ = parse_event_block(&block);
            }
        }
        for block in parser.flush() {
            let _ = parse_event_block(&block);
        }
    }

    #[test]
    fn event_block_parser_never_panics(block in any::<String>()) {
        let _ = parse_event_block(&block);
    }

    #[test]
    fn stream_state_never_panics_on_arbitrary_json(
        chunks in prop::collection::vec(json_value("\\PC{0,8}"), 0..8),
        field in prop::option::of("[a-z_]{1,10}"),
    ) {
        let mut state = StreamState::new();
        for chunk in &chunks {
            let _ = state.handle(chunk, field.as_deref());
        }
        let _ = state.finish(None);
    }

    /// The blocks do not depend on where the reads were split. LF line endings
    /// and ASCII only: the ignored tests below cover a split CRLF and a split
    /// multibyte character, which do not hold yet.
    #[test]
    fn blocks_do_not_depend_on_read_boundaries(
        text in "[ -~\\n]{0,200}",
        cuts in prop::collection::vec(any::<usize>(), 0..8),
    ) {
        let whole = blocks_for(text.as_bytes(), &[]);
        let split = blocks_for(text.as_bytes(), &cuts);
        prop_assert_eq!(whole, split);
    }

    #[test]
    fn interleaved_tool_call_fragments_reassemble(
        plans in prop::collection::vec(planned("\\PC{0,8}"), 1..4),
        order in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        let mut state = StreamState::new();
        for chunk in chunks_for(&plans, &order) {
            state.handle(&chunk, None);
        }
        let (calls, stop) = finish_tool_calls(state);
        let expected: Vec<ToolCall> = plans.iter().map(|p| p.call.clone()).collect();
        prop_assert_eq!(calls, expected);
        prop_assert_eq!(stop, StopReason::ToolCalls);
    }

    /// The same, through the wire format and arbitrary read boundaries.
    #[test]
    fn tool_calls_survive_the_wire_and_read_boundaries(
        plans in prop::collection::vec(planned("[ -~]{0,8}"), 1..4),
        order in prop::collection::vec(any::<u8>(), 0..24),
        cuts in prop::collection::vec(any::<usize>(), 0..12),
    ) {
        let mut wire = String::new();
        for chunk in chunks_for(&plans, &order) {
            let _ = write!(wire, "data: {chunk}\n\n");
        }
        wire.push_str("data: [DONE]\n\n");

        let mut state = StreamState::new();
        let mut done = false;
        for block in blocks_for(wire.as_bytes(), &cuts) {
            match parse_event_block(&block) {
                Some(SseEvent::Data(value)) => { state.handle(&value, None); }
                Some(SseEvent::Done) => done = true,
                None => {}
            }
        }
        prop_assert!(done);
        let (calls, _) = finish_tool_calls(state);
        let expected: Vec<ToolCall> = plans.iter().map(|p| p.call.clone()).collect();
        prop_assert_eq!(calls, expected);
    }
}

/// A huge `index` from the server must not allocate per-index state.
#[test]
fn oversized_tool_call_index_is_ignored() {
    let mut state = StreamState::new();
    let chunk = json!({ "choices": [{ "delta": { "tool_calls": [
        { "index": u64::from(u32::MAX), "id": "x", "function": { "name": "n", "arguments": "{}" } },
        { "index": u64::MAX, "id": "y", "function": { "name": "n", "arguments": "{}" } },
        { "index": 0, "id": "ok", "function": { "name": "n", "arguments": "{}" } },
    ] } }] });
    state.handle(&chunk, None);
    let (calls, _) = finish_tool_calls(state);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, "ok");
}

/// Known bug: a CRLF split across two reads is normalised twice, so the lone
/// `\r` at the end of the first read becomes a `\n` and the `\n` at the start of
/// the second read adds another. That fakes a blank line and dispatches the
/// event early, splitting what should be one event with two data lines. Run
/// with `--ignored` to reproduce.
#[test]
#[ignore = "fails until a trailing CR is held back until the next read"]
fn crlf_split_across_reads_is_one_line_ending() {
    let wire = b"data: a\r\ndata: b\r\n\r\n";
    let cr = wire.iter().position(|b| *b == b'\r').unwrap();
    assert_eq!(blocks_for(wire, &[]), blocks_for(wire, &[cr + 1]));
}

/// Known bug: `feed` decodes each read with `from_utf8_lossy`, so a multibyte
/// character split across two reads turns into U+FFFD. Bytes of an incomplete
/// sequence should be buffered until the rest arrives. Run with `--ignored`
/// to reproduce.
#[test]
#[ignore = "fails until the parser buffers incomplete UTF-8 sequences"]
fn multibyte_characters_survive_a_split_read() {
    let wire = "data: {\"choices\":[{\"delta\":{\"content\":\"\u{20ac}\"}}]}\n\n".as_bytes();
    let euro = wire.iter().position(|b| *b == 0xe2).unwrap();
    assert_eq!(
        blocks_for(wire, &[]),
        blocks_for(wire, &[euro + 1]),
        "splitting inside the euro sign changed the block"
    );
}
