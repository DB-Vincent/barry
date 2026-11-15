#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Budgets through the real binary: exit code 4 when a budget is exceeded,
/// exit code 2 for a budget setting that cannot be enforced.
use barry_testkit::{FakeLlm, Reply};

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd.env(
        "XDG_STATE_HOME",
        std::env::temp_dir().join(format!("barry-cli-budget-state-{}", std::process::id())),
    );
    cmd
}

fn tool_then_text() -> Vec<Reply> {
    vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: serde_json::json!({ "command": "echo hi" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn max_tokens_flag_exits_4_and_reports_the_stop_in_json() {
    let llm = FakeLlm::start(tool_then_text()).await;
    let out = barry()
        .args(["-p", "hi", "--json", "--max-tokens", "1"])
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");

    assert_eq!(out.status.code(), Some(4), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last: serde_json::Value =
        serde_json::from_str(stdout.lines().last().expect("output")).expect("json");
    // The last line is the run summary (#37), which carries the stop reason.
    assert_eq!(
        last["RunSummary"]["stop_reason"]["BudgetExceeded"],
        "Tokens"
    );
    assert_eq!(last["RunSummary"]["exit_code"], 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn budgets_section_in_config_applies() {
    let llm = FakeLlm::start(tool_then_text()).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, "[budgets]\nmax_total_tokens = 1\n").unwrap();
    let out = barry()
        .args(["-p", "hi"])
        .env("BARRY_CONFIG", &cfg)
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");

    assert_eq!(out.status.code(), Some(4), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_limit_without_prices_exits_2() {
    let out = barry()
        .args(["-p", "hi", "--max-cost-usd", "1.0"])
        .output()
        .await
        .expect("barry runs");

    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("price_input_per_mtok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_budget_value_in_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, "[budgets]\nmax_wall_secs = \"soon\"\n").unwrap();
    let out = barry()
        .args(["-p", "hi"])
        .env("BARRY_CONFIG", &cfg)
        .output()
        .await
        .expect("barry runs");

    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("max_wall_secs"));
}
