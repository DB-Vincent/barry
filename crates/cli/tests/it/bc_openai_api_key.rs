#![allow(clippy::unwrap_used, clippy::expect_used)]

/// `OPENAI_API_KEY` is sent as a bearer token to the OpenAI-compatible
/// provider, and is not sent to a plain-http server that is not loopback.
use barry_testkit::{FakeLlm, Reply};

fn barry(base_url: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG").env_remove("BARRY_PROVIDER");
    cmd.env(
        "XDG_STATE_HOME",
        std::env::temp_dir().join(format!(
            "barry-openai-key-test-state-{}",
            std::process::id()
        )),
    );
    cmd.env("BARRY_BASE_URL", base_url)
        .env("OPENAI_API_KEY", "sk-test-0123456789012345678901")
        .args(["-p", "hi"]);
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_api_key_is_sent_to_a_loopback_server() {
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "ok".into(),
    }])
    .await;
    let out = barry(&llm.uri()).output().await.unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        llm.last_auth_header().as_deref(),
        Some("Bearer sk-test-0123456789012345678901")
    );
}
