/// BC-1.6 A 429 followed by a success completes normally. A 401 gives an
/// auth error naming the provider, and the error text does not contain the
/// API key.
use barry_llm::{Compat, LlmError, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

fn provider(llm: &FakeLlm, api_key_env: Option<&str>) -> OpenAiProvider {
    OpenAiProvider::new(
        "test-model".to_string(),
        llm.uri().parse::<reqwest::Url>().unwrap(),
        api_key_env.map(String::from),
        1024,
        Compat::default(),
    )
}

async fn collect(provider: OpenAiProvider) -> Vec<Result<LlmEvent, LlmError>> {
    let req = LlmRequest {
        messages: vec![Message::User {
            content: "hi".to_string(),
        }],
        tools: vec![],
    };
    let mut stream = provider.stream(req, CancellationToken::new());
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn bc_1_6_429_then_success() {
    // First attempt returns 429; the retry returns a normal streamed reply.
    let sse = concat!(
        r#"data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );
    let llm = FakeLlm::start(vec![
        Reply::HttpStatus { status: 429 },
        Reply::RawSse {
            sse: sse.to_string(),
        },
    ])
    .await;

    let provider = provider(&llm, None);
    let events = collect(provider).await;

    let mut done: Option<&LlmEvent> = None;
    for e in events.iter().flatten() {
        if matches!(e, LlmEvent::Done { .. }) {
            done = Some(e);
            break;
        }
    }
    let done = done.expect("expected a Done event");

    match done {
        LlmEvent::Done { stop, .. } => assert_eq!(*stop, StopReason::Stop),
        _ => panic!("expected a Done event"),
    }
}

#[tokio::test]
async fn bc_1_6_401_auth_error_no_key_leak() {
    // 401 is not retryable: one attempt, then an auth error.
    let llm = FakeLlm::start(vec![Reply::HttpStatus { status: 401 }]).await;

    std::env::set_var("BARRY_TEST_KEY", "sk-secret-key");
    let provider = provider(&llm, Some("BARRY_TEST_KEY"));
    let events = collect(provider).await;

    let err = events
        .into_iter()
        .find_map(Result::err)
        .expect("expected an error event");

    let err_text = err.to_string();
    assert!(
        matches!(&err, LlmError::Auth { provider } if provider == "openai"),
        "expected Auth error naming the provider, got {err_text}"
    );
    assert!(
        !err_text.contains("sk-secret-key"),
        "error text must not contain the API key"
    );
}
