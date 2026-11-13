/// BC-4.1 `echo x > ../outside/f` run by bash does not create the file,
/// even though the rule layer asked and the user approved it "once" without
/// a grant. This proves the sandbox is a separate layer from policy.
use barry_testkit::{FakeLlm, Reply};
use serde_json::json;

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_1_sandbox_blocks_outside_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let target = outside.join("f");

    let llm = FakeLlm::start(vec![
        // Model asks to write outside cwd; user approves "once".
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "echo x > ../outside/f" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ])
    .await;

    let out = barry()
        .args(["-p", "write to ../outside/f"])
        .arg("--json")
        .env("BARRY_BASE_URL", llm.uri())
        .current_dir(dir.path())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed, stderr: {stderr}"
    );

    // The sandbox blocked the write even though the user approved it.
    assert!(
        !target.exists(),
        "sandbox must block write outside cwd even with user approval"
    );
}
