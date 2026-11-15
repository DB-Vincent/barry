/// BC-1.2 Given a tool call whose name and arguments arrive split across chunks,
/// when the provider receives it, then one ToolCall is returned with fully
/// parsed JSON arguments.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn bc_1_2_split_tool_call_is_assembled() {
    // The name and id come first, then the arguments JSON is cut mid-string
    // and continued in a second chunk.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read","arguments":"{\"path\":"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"README.md\"}"}}]}}]}"#,
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
            content: "read the readme".to_string(),
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

    assert_eq!(tool_calls.len(), 1, "expected exactly one tool call");
    let call = &tool_calls[0];
    assert_eq!(call.id, "call_1");
    assert_eq!(call.name, "read");
    assert_eq!(
        call.arguments,
        json!({ "path": "README.md" }),
        "arguments must be concatenated across chunks and parsed as JSON, got {:?}",
        call.arguments
    );
}
