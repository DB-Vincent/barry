/// BC-1.4 `finish_reason: "length"` gives StopReason::Length; `finish_reason:
/// "stop"` with tool calls present gives ToolCalls.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

/// Run one raw SSE reply through the provider and return the Done payload.
async fn run(sse: &str) -> (Message, StopReason) {
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
            content: "hi".to_string(),
        }],
        tools: vec![],
    };
    let mut stream = provider.stream(req, CancellationToken::new());

    while let Some(event) = stream.next().await {
        if let LlmEvent::Done { message, stop, .. } = event.unwrap() {
            return (message, stop);
        }
    }
    panic!("expected a Done event");
}

#[tokio::test]
async fn bc_1_4_length_maps_to_length() {
    // A truncated reply: the model ran out of tokens mid-answer, so the
    // content that did arrive must be kept.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"content":"the answer is"},"finish_reason":"length"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    let (message, stop) = run(sse).await;
    assert_eq!(stop, StopReason::Length);

    let Message::Assistant { content, .. } = message else {
        panic!("expected an Assistant message");
    };
    assert_eq!(content.as_deref(), Some("the answer is"));
}

#[tokio::test]
async fn bc_1_4_stop_with_tool_calls_is_tool_calls() {
    // The server says "stop" even though the same reply carried a tool call.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read","arguments":"{\"path\":\"a.rs\"}"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    let (message, stop) = run(sse).await;
    assert_eq!(
        stop,
        StopReason::ToolCalls,
        "a reply carrying tool calls must not report Stop"
    );

    let Message::Assistant { tool_calls, .. } = message else {
        panic!("expected an Assistant message");
    };
    assert_eq!(tool_calls.len(), 1);
}

#[tokio::test]
async fn bc_1_4_stop_without_tool_calls_stays_stop() {
    // The upgrade must only fire when calls are actually present.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"content":"done"},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    let (_, stop) = run(sse).await;
    assert_eq!(stop, StopReason::Stop);
}
