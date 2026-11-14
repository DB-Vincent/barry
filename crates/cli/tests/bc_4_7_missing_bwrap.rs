/// BC-4.7 On Linux with no `bwrap` on `PATH`, bash returns a clear
/// "bubblewrap not found" error, and the command does not run at all (a marker
/// file is not created).
use barry_testkit::{FakeLlm, Reply};
use serde_json::json;

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_4_7_missing_bwrap_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");

    // `echo x | tee marker` passes the rule layer (both segments are allowed)
    // and would create `marker` if it ran. With no bwrap on PATH it must not.
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "echo x | tee marker" }),
        },
        Reply::Text {
            content: "could not run the command".to_string(),
        },
    ])
    .await;

    // A PATH with no bwrap in it. barry itself is launched by absolute path.
    let empty_path = dir.path().join("empty-path");
    std::fs::create_dir_all(&empty_path).expect("create empty path dir");

    let out = barry()
        .args(["-p", "write the marker"])
        .arg("--json")
        .env("PATH", &empty_path)
        .env("BARRY_BASE_URL", llm.uri())
        .current_dir(dir.path())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "barry should succeed (the error is a tool result), stderr: {stderr}"
    );

    // The command never ran.
    assert!(
        !marker.exists(),
        "command must not run when bwrap is missing"
    );

    // The model received a clear, actionable error.
    let saw_bwrap_error = llm.requests().iter().any(|req| {
        req["messages"]
            .as_array()
            .map(|msgs| {
                msgs.iter().any(|m| {
                    m["role"] == "tool"
                        && m["content"]
                            .as_str()
                            .map(|c| c.contains("bwrap") || c.contains("bubblewrap"))
                            .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });
    assert!(
        saw_bwrap_error,
        "the model should receive a clear bubblewrap error"
    );
}
