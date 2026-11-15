/// BC-1.1 Given a streamed text reply,
/// when the provider receives it, then it arrives as ≥2 TextDeltas
/// and the final message equals their concatenation.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::Message;
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn bc_1_1_streamed_text_concatenates() {
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "hello world".to_string(),
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
            content: "say hi".to_string(),
        }],
        tools: vec![],
    };

    let cancel = CancellationToken::new();
    let mut stream = provider.stream(req, cancel);

    let mut deltas = String::new();
    let mut delta_count = 0u32;
    let mut final_message = None;

    while let Some(event) = stream.next().await {
        match event.unwrap() {
            LlmEvent::TextDelta(text) => {
                deltas.push_str(&text);
                delta_count += 1;
            }
            LlmEvent::Done { message, .. } => {
                final_message = Some(message);
            }
            _ => {}
        }
    }

    assert!(
        delta_count >= 2,
        "expected at least 2 TextDeltas, got {}",
        delta_count
    );

    let Message::Assistant { content, .. } = final_message.unwrap() else {
        panic!("expected Assistant message in Done event");
    };
    assert_eq!(content.unwrap(), deltas);
}
