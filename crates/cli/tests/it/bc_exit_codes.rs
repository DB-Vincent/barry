#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Headless exit codes and the final JSON summary line.
use barry_testkit::{FakeLlm, Reply};

struct Run {
    out: std::process::Output,
    dir: tempfile::TempDir,
}

impl Run {
    fn code(&self) -> Option<i32> {
        self.out.status.code()
    }

    /// The last stdout line, parsed.
    fn summary(&self) -> serde_json::Value {
        let stdout = String::from_utf8_lossy(&self.out.stdout);
        let line = stdout.lines().last().expect("some output");
        let value: serde_json::Value = serde_json::from_str(line).expect("json line");
        value["RunSummary"].clone()
    }
}

async fn run(script: Vec<Reply>, extra: &[&str]) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let llm = FakeLlm::start(script).await;
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .env_remove("BARRY_CONFIG")
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("BARRY_BASE_URL", llm.uri())
        .current_dir(dir.path())
        .args(["-p", "go", "--json"])
        .args(extra)
        .output()
        .await
        .expect("barry runs");
    Run { out, dir }
}

fn text(content: &str) -> Reply {
    Reply::Text {
        content: content.to_string(),
    }
}

fn tool(name: &str, arguments: serde_json::Value) -> Reply {
    Reply::Tool {
        name: name.to_string(),
        arguments,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clean_run_exits_0_and_summarises_usage() {
    let r = run(vec![text("hi")], &[]).await;

    assert_eq!(r.code(), Some(0), "{:?}", r.out);
    let s = r.summary();
    assert_eq!(s["stop_reason"], "Stop");
    assert_eq!(s["exit_code"], 0);
    assert_eq!(s["turn_limit_reached"], false);
    assert_eq!(s["denied_actions"], 0);
    assert_eq!(s["files_changed"], serde_json::json!([]));
    assert_eq!(s["usage"]["input_tokens"], 10);
    assert_eq!(s["usage"]["output_tokens"], 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_action_exits_5_and_is_counted() {
    // No approval file: the write outside the cwd needs approval and is denied.
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("nope.txt");
    let r = run(
        vec![
            tool(
                "write",
                serde_json::json!({ "path": target, "content": "x" }),
            ),
            text("could not write"),
        ],
        &[],
    )
    .await;

    assert_eq!(r.code(), Some(5), "{:?}", r.out);
    assert!(!target.exists());
    let s = r.summary();
    assert_eq!(s["stop_reason"], "Stop");
    assert_eq!(s["exit_code"], 5);
    assert_eq!(s["denied_actions"], 1);
    assert_eq!(s["files_changed"], serde_json::json!([]));
    // Usage is summed over both requests.
    assert_eq!(s["usage"]["input_tokens"], 20);
}

#[tokio::test(flavor = "multi_thread")]
async fn files_changed_lists_written_paths_as_absolute() {
    let r = run(
        vec![
            tool(
                "write",
                serde_json::json!({ "path": "out.txt", "content": "x" }),
            ),
            text("done"),
        ],
        &[],
    )
    .await;

    assert_eq!(r.code(), Some(0), "{:?}", r.out);
    let written = r.dir.path().join("out.txt");
    assert!(written.exists());
    let files = r.summary()["files_changed"].clone();
    let files: Vec<std::path::PathBuf> = serde_json::from_value(files).unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].is_absolute());
    assert_eq!(files[0].file_name().unwrap(), "out.txt");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_error_exits_1_and_the_summary_says_error() {
    let r = run(vec![Reply::HttpStatus { status: 400 }], &[]).await;

    assert_eq!(r.code(), Some(1), "{:?}", r.out);
    let s = r.summary();
    assert!(s["stop_reason"]["Error"].is_string(), "{s}");
    assert_eq!(s["exit_code"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_config_error_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, "not = = toml").unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .env("BARRY_CONFIG", &cfg)
        .args(["-p", "go", "--json"])
        .output()
        .await
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "no run, so no summary");
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_mode_prints_no_summary() {
    let dir = tempfile::tempdir().unwrap();
    let llm = FakeLlm::start(vec![text("hi")]).await;
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .env_remove("BARRY_CONFIG")
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("BARRY_BASE_URL", llm.uri())
        .args(["-p", "go"])
        .output()
        .await
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
}
