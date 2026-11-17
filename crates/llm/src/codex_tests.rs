//! Unit tests for the Codex provider: prompt building and event folding.

use barry_protocol::{Message, StopReason, Usage};

use crate::LlmEvent;
use crate::codex::{CodexState, build_prompt};

#[test]
fn prompt_flattens_history_in_order() {
    let prompt = build_prompt(&[
        Message::System {
            content: "sys".into(),
        },
        Message::User {
            content: "q1".into(),
        },
        Message::Assistant {
            content: Some("a1".into()),
            reasoning: None,
            tool_calls: vec![],
        },
        Message::Tool {
            tool_call_id: "x".into(),
            content: "out".into(),
            ok: true,
        },
    ]);
    assert_eq!(
        prompt,
        "sys\n\nUser:\nq1\n\nAssistant:\na1\n\nTool result:\nout\n\n"
    );
}

#[test]
fn agent_messages_and_usage_are_collected() {
    let mut state = CodexState::default();
    let mut deltas = Vec::new();
    for line in [
        r#"{"type":"thread.started","thread_id":"t"}"#,
        r#"{"type":"item.started","item":{"id":"1","type":"command_execution","command":"ls"}}"#,
        r#"{"type":"item.completed","item":{"id":"2","type":"agent_message","text":"first"}}"#,
        "not json",
        r#"{"type":"item.completed","item":{"id":"3","type":"agent_message","text":"second"}}"#,
        r#"{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":5}}"#,
    ] {
        deltas.extend(state.handle_line(line));
    }
    assert_eq!(deltas.len(), 2);
    let LlmEvent::Done {
        message,
        stop,
        usage,
    } = state.finish(None)
    else {
        panic!("expected Done");
    };
    assert_eq!(stop, StopReason::Stop);
    assert_eq!(
        usage,
        Some(Usage {
            input_tokens: 10,
            output_tokens: 5
        })
    );
    let Message::Assistant {
        content,
        tool_calls,
        ..
    } = message
    else {
        panic!("expected assistant");
    };
    assert_eq!(content.as_deref(), Some("first\n\nsecond"));
    assert_eq!(tool_calls.len(), 0);
}

#[test]
fn failure_events_become_a_generic_error() {
    let mut state = CodexState::default();
    state.handle_line(r#"{"type":"error","error":{"message":"secret detail"}}"#);
    let LlmEvent::Done { stop, .. } = state.finish(None) else {
        panic!("expected Done");
    };
    assert_eq!(stop, StopReason::Error("codex reported an error".into()));
}
