/// BC-1.5 Invalid JSON tool arguments give a ToolCall whose arguments is the
/// raw string. This is not a provider error.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn bc_1_5_invalid_json_args_are_raw_string() {
    // Chunk 1 opens a JSON object; chunk 2 adds garbage that keeps it invalid.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read","arguments":"{\"path\":"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"nope"}}]}}]}"#,
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
            content: "read".to_string(),
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
    assert_eq!(
        stop,
        StopReason::ToolCalls,
        "invalid args must not produce an error stop reason"
    );

    let Message::Assistant { tool_calls, .. } = message else {
        panic!("expected an Assistant message");
    };

    assert_eq!(
        tool_calls.len(),
        1,
        "invalid JSON must not drop the tool call"
    );
    let call = &tool_calls[0];
    assert_eq!(call.id, "call_1");
    assert_eq!(call.name, "read");
    assert_eq!(
        call.arguments,
        Value::String("{\"path\":nope".to_string()),
        "invalid JSON must be kept as the raw string, not parsed or nulled"
    );
}
