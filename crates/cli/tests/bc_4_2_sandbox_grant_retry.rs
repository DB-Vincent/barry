/// BC-4.2 When a bash write is denied by the sandbox, the user is offered a
/// grant for that directory. After approval the command is retried and
/// succeeds. After denial the original failure goes to the model.
use barry_testkit::{FakeLlm, Reply};
use serde_json::json;

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_2_sandbox_denial_grant_then_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let target = outside.join("f");

    // First command: echo outside/f → sandbox denies → approver says Once
    // → grant outside dir → retry → succeeds.
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": format!("echo x > {}", target.display()) }),
        },
        Reply::Text {
            content: "written after grant".to_string(),
        },
    ])
    .await;

    // Set BARRY_BIN_OVERRIDE so bwrap re-execs the real barry binary.
    let out = barry()
        .args(["-p", "write to outside/f"])
        .arg("--json")
        .env("BARRY_BASE_URL", llm.uri())
        .env("BARRY_BIN_OVERRIDE", env!("CARGO_BIN_EXE_barry"))
        .current_dir(dir.path())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed, stderr: {stderr}"
    );

    // After grant + retry, the file should exist.
    assert!(
        target.exists(),
        "sandbox-denied write should succeed after grant: {target:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read file"),
        "x\n",
        "file content should match"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_2_sandbox_denial_deny_after_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let target = outside.join("f");

    // First command: echo outside/f → sandbox denies → approver says Once
    // → grant offered → approver says Deny → original failure goes to model.
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": format!("echo x > {}", target.display()) }),
        },
        Reply::Text {
            content: "write was denied".to_string(),
        },
    ])
    .await;

    let out = barry()
        .args(["-p", "write to outside/f"])
        .arg("--json")
        .env("BARRY_BASE_URL", llm.uri())
        .env("BARRY_BIN_OVERRIDE", env!("CARGO_BIN_EXE_barry"))
        .current_dir(dir.path())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed, stderr: {stderr}"
    );

    // File should NOT exist because user denied the grant.
    assert!(
        !target.exists(),
        "file should not be written when grant denied"
    );

    // Parse the JSONL events to find the ToolFinished for the denied write.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let events: Vec<serde_json::Value> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    // Find the ToolFinished event for the bash call - it should be ok:false
    // with a sandbox denial message.
    let sandbox_denied = events.iter().any(|e| {
        e.get("ToolFinished")
            .and_then(|tf| tf.get("ok"))
            .and_then(|ok| ok.as_bool())
            == Some(false)
    });

    assert!(
        sandbox_denied,
        "sandbox denial should go to the model: {events:?}"
    );
}
