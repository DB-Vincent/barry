/// BC-4.4 `env` run in bash shows no variable from the test environment named
/// `OPENAI_API_KEY` or `TEST_SECRET_TOKEN`.
use barry_testkit::{FakeLlm, Reply};
use serde_json::json;

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd.env(
        "XDG_STATE_HOME",
        std::env::temp_dir().join(format!("barry-cli-test-state-{}", std::process::id())),
    );
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_4_sandbox_env_no_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");

    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "env" }),
        },
        Reply::Text {
            content: "no secrets found".to_string(),
        },
    ])
    .await;

    // Set secret env vars in the test environment - they should NOT be
    // passed into the sandbox.
    let out = barry()
        .args(["-p", "check env for secrets"])
        .arg("--json")
        .env("BARRY_BASE_URL", llm.uri())
        .env("OPENAI_API_KEY", "sk-test-secret-key")
        .env("TEST_SECRET_TOKEN", "test-secret-token-value")
        .current_dir(dir.path())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed, stderr: {stderr}"
    );

    // env inside the sandbox should not contain the secrets.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("OPENAI_API_KEY"),
        "OPENAI_API_KEY must not be in sandbox env: {stdout}"
    );
    assert!(
        !stdout.contains("TEST_SECRET_TOKEN"),
        "TEST_SECRET_TOKEN must not be in sandbox env: {stdout}"
    );
}
