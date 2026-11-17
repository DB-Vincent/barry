#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

/// The Anthropic provider, selected with `BARRY_PROVIDER=anthropic`, sends the
/// token printed by `ant` as a bearer token, parses the Messages API stream,
/// maps credential and auth failures to generic errors, and never prints the
/// token. A fake `ant` on `PATH` and `FakeLlm` stand in for the real services.
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use barry_testkit::{FakeLlm, Reply};

const TOKEN: &str = "sk-ant-oat01-faketokenfaketokenfaketoken";

fn fake_ant(dir: &Path, body: &str) {
    let path = dir.join("ant");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn barry(ant_dir: &Path, base_url: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd.env(
        "XDG_STATE_HOME",
        std::env::temp_dir().join(format!("barry-anthropic-test-state-{}", std::process::id())),
    );
    let path = format!(
        "{}:{}",
        ant_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path)
        .env("BARRY_PROVIDER", "anthropic")
        .env("BARRY_BASE_URL", base_url)
        .args(["--model", "claude-test", "-p", "hi"]);
    cmd
}

fn sse(events: &[serde_json::Value]) -> String {
    events
        .iter()
        .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn anthropic_provider_sends_the_ant_token_and_prints_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    fake_ant(
        dir.path(),
        &format!(
            r#"[ "$1 $2 $3" = "auth print-credentials --access-token" ] && echo {TOKEN} || exit 9"#
        ),
    );
    let llm = FakeLlm::start(vec![Reply::RawSse {
        sse: sse(&[
            serde_json::json!({"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1}}}),
            serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello from claude"}}),
            serde_json::json!({"type":"content_block_stop","index":0}),
            serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}),
            serde_json::json!({"type":"message_stop"}),
        ]),
    }])
    .await;

    let out = barry(dir.path(), &llm.uri()).output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout.trim(), "hello from claude");
    assert_eq!(llm.last_auth_header(), Some(format!("Bearer {TOKEN}")));
    assert!(!stdout.contains(TOKEN) && !stderr.contains(TOKEN));

    let request = llm.requests().pop().expect("one request");
    assert_eq!(request["model"], "claude-test");
    assert_eq!(request["stream"], true);
    assert_eq!(request["messages"][0]["role"], "user");
}

#[tokio::test(flavor = "multi_thread")]
async fn anthropic_provider_maps_a_401_to_an_auth_error_without_the_token() {
    let dir = tempfile::tempdir().unwrap();
    fake_ant(dir.path(), &format!("echo {TOKEN}"));
    let llm = FakeLlm::start(vec![Reply::HttpStatus { status: 401 }]).await;

    let out = barry(dir.path(), &llm.uri()).output().await.unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert_ne!(out.status.code(), Some(0));
    assert!(all.contains("auth error for provider anthropic"), "{all}");
    assert!(!all.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn anthropic_provider_reports_missing_credentials_and_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fake_ant(dir.path(), "echo 'secret detail' >&2; exit 1");
    let llm = FakeLlm::start(vec![]).await;

    let out = barry(dir.path(), &llm.uri()).output().await.unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert_ne!(out.status.code(), Some(0));
    assert!(all.contains("run `/auth login anthropic`"), "{all}");
    assert!(!all.contains("secret detail"));
    assert!(llm.requests().is_empty(), "no request without a token");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_provider_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = barry(dir.path(), "http://127.0.0.1:9")
        .env("BARRY_PROVIDER", "nope")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("BARRY_PROVIDER"));
}
