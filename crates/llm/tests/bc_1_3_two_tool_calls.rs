/// BC-1.3 Given two tool calls in one reply,
/// when the provider receives them, then both are returned with their ids
/// in index order.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn bc_1_3_two_tool_calls_in_index_order() {
    // Index 1 arrives first, index 0 second. Argument fragments are
    // deliberately interleaved, and each JSON is cut mid-string.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"edit","arguments":""}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"read","arguments":""}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"path\":\"b"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"a"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":".rs\"}"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":".rs\"}"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"finish_reason":"tool_calls"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    let llm = FakeLlm::start(vec![Reply::RawSse {
        sse: sse.to_string(),
    }])
    .await;

    let provider = OpenAiProvider::new(
        "test-model".to_string(),
        llm.uri().parse::<reqwest::Url>().unwrap(),
        None,
        1024,
        Compat::default(),
    );

    let req = LlmRequest {
        messages: vec![Message::User {
            content: "read a.rs and edit b.rs".to_string(),
        }],
        tools: vec![],
    };
    let mut stream = provider.stream(req, CancellationToken::new());

    let mut done = None;
    while let Some(event) = stream.next().await {
        if let LlmEvent::Done { message, stop, .. } = event.unwrap() {
            done = Some((message, stop));
        }
    }

    let (message, stop) = done.expect("expected a Done event");
    assert_eq!(stop, StopReason::ToolCalls);

    let Message::Assistant { tool_calls, .. } = message else {
        panic!("expected an Assistant message");
    };

    assert_eq!(tool_calls.len(), 2, "expected two tool calls");

    // The key assertion: index order, not arrival order.
    let ids: Vec<&str> = tool_calls.iter().map(|call| call.id.as_str()).collect();
    assert_eq!(
        ids,
        ["call_a", "call_b"],
        "tool calls must be ordered by index"
    );

    assert_eq!(tool_calls[0].name, "read");
    assert_eq!(tool_calls[0].arguments, json!({ "path": "a.rs" }));

    assert_eq!(tool_calls[1].name, "edit");
    assert_eq!(tool_calls[1].arguments, json!({ "path": "b.rs" }));
}
