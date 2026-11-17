//! Unit tests for the Anthropic provider: request mapping and stream folding.

use barry_protocol::{Message, StopReason, ToolCall, Usage};
use reqwest::Url;
use serde_json::{Value, json};

use crate::LlmEvent;
use crate::anthropic::{AnthropicState, build_messages, map_stop_reason, messages_url};

fn run(events: &[Value]) -> (Vec<LlmEvent>, LlmEvent) {
    let mut state = AnthropicState::new();
    let mut out = Vec::new();
    for event in events {
        out.extend(state.handle(event));
    }
    (out, state.finish(None))
}

#[test]
fn system_is_hoisted_and_tool_results_are_merged() {
    let messages = vec![
        Message::System {
            content: "be brief".into(),
        },
        Message::User {
            content: "hi".into(),
        },
        Message::Assistant {
            content: Some("ok".into()),
            reasoning: None,
            tool_calls: vec![
                ToolCall {
                    id: "a".into(),
                    name: "bash".into(),
                    arguments: json!({"cmd": "ls"}),
                },
                ToolCall {
                    id: "b".into(),
                    name: "read".into(),
                    arguments: Value::String("{bad".into()),
                },
            ],
        },
        Message::Tool {
            tool_call_id: "a".into(),
            content: "x".into(),
            ok: true,
        },
        Message::Tool {
            tool_call_id: "b".into(),
            content: "denied".into(),
            ok: false,
        },
    ];
    let (system, out) = build_messages(&messages);
    assert_eq!(system, "be brief");
    assert_eq!(out.len(), 3);
    assert_eq!(out[1]["content"][1]["input"], json!({"cmd": "ls"}));
    assert_eq!(out[1]["content"][2]["input"], json!({}));
    let results = out[2]["content"].as_array().expect("blocks");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["is_error"], json!(false));
    assert_eq!(results[1]["is_error"], json!(true));
    assert_eq!(results[1]["tool_use_id"], json!("b"));
}

#[test]
fn empty_assistant_turn_gets_placeholder_text() {
    let (_, out) = build_messages(&[Message::Assistant {
        content: None,
        reasoning: None,
        tool_calls: vec![],
    }]);
    assert_eq!(out[0]["content"][0]["type"], json!("text"));
}

#[test]
fn text_stream_with_usage() {
    let (deltas, done) = run(&[
        json!({"type":"message_start","message":{"usage":{"input_tokens":11,"cache_read_input_tokens":4,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"1 + "}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"1 = 2"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}),
        json!({"type":"message_stop"}),
    ]);
    assert_eq!(deltas.len(), 2);
    let LlmEvent::Done {
        message,
        stop,
        usage,
    } = done
    else {
        panic!("expected Done");
    };
    assert_eq!(stop, StopReason::Stop);
    assert_eq!(
        usage,
        Some(Usage {
            input_tokens: 15,
            output_tokens: 12
        })
    );
    let Message::Assistant { content, .. } = message else {
        panic!("expected assistant");
    };
    assert_eq!(content.as_deref(), Some("1 + 1 = 2"));
}

#[test]
fn tool_use_assembles_split_json_and_thinking() {
    let (deltas, done) = run(&[
        json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"s"}}),
        json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"bash","input":{}}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":"}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"ls\"}"}}),
        json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"t2","name":"noargs","input":{}}}),
        json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}),
        json!({"type":"message_stop"}),
    ]);
    assert!(matches!(&deltas[0], LlmEvent::ReasoningDelta(t) if t == "hmm"));
    let LlmEvent::Done { message, stop, .. } = done else {
        panic!("expected Done");
    };
    assert_eq!(stop, StopReason::ToolCalls);
    let Message::Assistant {
        tool_calls,
        reasoning,
        ..
    } = message
    else {
        panic!("expected assistant");
    };
    assert_eq!(reasoning.as_deref(), Some("hmm"));
    assert_eq!(tool_calls.len(), 2);
    assert_eq!(tool_calls[0].arguments, json!({"cmd": "ls"}));
    assert_eq!(tool_calls[1].arguments, json!({}));
}

#[test]
fn error_event_becomes_error_stop_without_message_text() {
    let (_, done) = run(&[
        json!({"type":"error","error":{"type":"overloaded_error","message":"secret detail"}}),
    ]);
    let LlmEvent::Done { stop, .. } = done else {
        panic!("expected Done");
    };
    assert_eq!(
        stop,
        StopReason::Error("provider stream error: overloaded_error".into())
    );
}

#[test]
fn stop_reasons_map() {
    assert_eq!(map_stop_reason("max_tokens"), StopReason::Length);
    assert_eq!(map_stop_reason("refusal"), StopReason::ContentFilter);
    assert_eq!(map_stop_reason("end_turn"), StopReason::Stop);
    assert_eq!(map_stop_reason("brand_new"), StopReason::Stop);
}

#[test]
fn out_of_range_block_index_is_ignored() {
    let (_, done) = run(&[
        json!({"type":"content_block_start","index":4_000_000_000_u64,"content_block":{"type":"tool_use","id":"x","name":"y","input":{}}}),
    ]);
    let LlmEvent::Done { message, .. } = done else {
        panic!("expected Done");
    };
    let Message::Assistant { tool_calls, .. } = message else {
        panic!("expected assistant");
    };
    assert_eq!(tool_calls.len(), 0);
}

#[test]
fn url_keeps_base_path() {
    let base = Url::parse("https://example.com/proxy").expect("url");
    assert_eq!(
        messages_url(&base).expect("join").as_str(),
        "https://example.com/proxy/v1/messages"
    );
}
