/// BC-1.9 With `reasoning_field = "reasoning"`, deltas in that field arrive
/// as `ReasoningDelta` and never as text.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn bc_1_9_reasoning_deltas_not_text() {
    // Each delta carries only the `reasoning` field; nothing should surface
    // as text.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"reasoning":"think"}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"delta":{"reasoning":"ing"},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    let llm = FakeLlm::start(vec![Reply::RawSse {
        sse: sse.to_string(),
    }])
    .await;

    let compat = Compat {
        reasoning_field: Some("reasoning".to_string()),
        ..Default::default()
    };

    let provider = OpenAiProvider::new(
        "test-model".to_string(),
        llm.uri().parse::<reqwest::Url>().unwrap(),
        None,
        1024,
        compat,
    );

    let req = LlmRequest {
        messages: vec![Message::User {
            content: "think about it".to_string(),
        }],
        tools: vec![],
    };
    let mut stream = provider.stream(req, CancellationToken::new());

    let mut reasoning = String::new();
    let mut text = 0usize;
    let mut done_message: Option<Message> = None;
    let mut stop = None;

    while let Some(event) = stream.next().await {
        match event.unwrap() {
            LlmEvent::TextDelta(_) => text += 1,
            LlmEvent::ReasoningDelta(s) => reasoning.push_str(&s),
            LlmEvent::Done {
                message, stop: s, ..
            } => {
                stop = Some(s);
                done_message = Some(message);
                break;
            }
        }
    }

    assert_eq!(text, 0, "reasoning deltas must not appear as text");
    assert_eq!(reasoning, "thinking");
    assert_eq!(stop, Some(StopReason::Stop));

    let Message::Assistant {
        content,
        reasoning: msg_reasoning,
        ..
    } = done_message.expect("expected a Done message")
    else {
        panic!("expected an Assistant message");
    };
    assert_eq!(msg_reasoning.as_deref(), Some("thinking"));
    assert_eq!(content, None);
}
