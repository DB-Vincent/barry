/// BC-4.3 `cat ~/.ssh/id_test` in bash fails, and the model never receives
/// `FAKE-PRIVATE-KEY`.
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
async fn bc_4_3_sandbox_blocks_secret_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).expect("create .ssh dir");
    std::fs::write(ssh_dir.join("id_test"), "FAKE-PRIVATE-KEY").expect("write fake key");

    // BARRY_CONFIG points to a config with home set to our temp home,
    // read_deny including ~/.ssh.
    let config_path = dir.path().join("config.toml");
    let id_test_path = ssh_dir.join("id_test");
    let config_content = format!(
        "default_model = \"local\"\nmax_turns = 10\nread_deny = [\"{}\"]\n",
        id_test_path.display()
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "cat ~/.ssh/id_test" }),
        },
        Reply::Text {
            content: "I cannot read that".to_string(),
        },
    ])
    .await;

    let out = barry()
        .args(["-p", "cat the ssh key"])
        .arg("--json")
        .env("BARRY_CONFIG", &config_path)
        .env("HOME", &home)
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed, stderr: {stderr}"
    );

    // The model never receives the secret.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("FAKE-PRIVATE-KEY"),
        "secret must not reach the model: {stdout}"
    );
}
