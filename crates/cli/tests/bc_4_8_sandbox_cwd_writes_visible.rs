/// BC-4.8 Files created in cwd by bash are visible on the host afterwards,
/// so normal work still functions.
use barry_testkit::{FakeLlm, Reply};
use serde_json::json;

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_8_sandbox_cwd_writes_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("created_by_bash.txt");

    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "echo hello | tee created_by_bash.txt" }),
        },
        Reply::Text {
            content: "file created".to_string(),
        },
    ])
    .await;

    let out = barry()
        .args(["-p", "create a file"])
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

    // The file should exist on the host after the sandboxed command ran.
    assert!(
        target.exists(),
        "file created by bash in cwd should be visible on host: {target:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read file"),
        "hello\n",
        "file content should match"
    );
}
