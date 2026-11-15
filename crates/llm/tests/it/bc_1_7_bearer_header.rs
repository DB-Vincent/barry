/// BC-1.7 When `api_key_env` is set, the request carries
/// `Authorization: Bearer <key>`. When unset, no Authorization header.
use barry_llm::{Compat, LlmError, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use barry_testkit::{FakeLlm, Reply};
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

async fn run(
    script: Vec<Reply>,
    api_key_env: Option<&str>,
) -> (FakeLlm, Vec<Result<LlmEvent, LlmError>>) {
    let llm = FakeLlm::start(script).await;

    let provider = OpenAiProvider::new(
        "test-model".to_string(),
        llm.uri().parse::<reqwest::Url>().unwrap(),
        api_key_env.map(String::from),
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
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event);
    }
    (llm, events)
}

fn assert_done(events: &[Result<LlmEvent, LlmError>]) {
    let done = events
        .iter()
        .flatten()
        .find(|e| matches!(e, LlmEvent::Done { .. }))
        .expect("expected a Done event");
    match done {
        LlmEvent::Done { stop, .. } => assert_eq!(*stop, StopReason::Stop),
        _ => panic!("expected a Done event"),
    }
}

#[tokio::test]
async fn bc_1_7_key_set_sends_bearer_header() {
    std::env::set_var("BARRY_TEST_KEY_A", "sk-test-123");
    let (llm, events) = run(
        vec![Reply::Text {
            content: "hi".to_string(),
        }],
        Some("BARRY_TEST_KEY_A"),
    )
    .await;

    assert_done(&events);
    assert_eq!(
        llm.last_auth_header(),
        Some("Bearer sk-test-123".to_string())
    );
}

#[tokio::test]
async fn bc_1_7_key_unset_no_header() {
    let (llm, events) = run(
        vec![Reply::Text {
            content: "hi".to_string(),
        }],
        None,
    )
    .await;

    assert_done(&events);
    assert_eq!(llm.last_auth_header(), None);
}

#[tokio::test]
async fn bc_1_7_key_set_but_missing_env_no_header() {
    let (llm, events) = run(
        vec![Reply::Text {
            content: "hi".to_string(),
        }],
        Some("BARRY_TEST_KEY_DOES_NOT_EXIST"),
    )
    .await;

    assert_done(&events);
    assert_eq!(llm.last_auth_header(), None);
}
