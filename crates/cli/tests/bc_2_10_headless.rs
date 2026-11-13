/// BC-2.10 Headless `barry -p "hi"` prints the final answer to stdout and
/// exits 0. `--json` prints one valid JSON object per line, ending with
/// `TurnFinished`.
///
/// The provider is driven over real HTTP by `testkit::FakeLlm`, and the real
/// binary is spawned, so this covers clap parsing, config loading, provider
/// wiring, the event drain and the exit code at once.
use barry_testkit::{FakeLlm, Reply};

fn barry() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    // Never let the developer's real config leak into an acceptance test.
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_2_10_headless_prints_the_final_answer_and_exits_0() {
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "hello from barry".to_string(),
    }])
    .await;

    let out = barry()
        .arg("-p")
        .arg("hi")
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello from barry",
        "the final assistant text goes to stdout"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_2_10_json_writes_one_object_per_line_ending_with_turn_finished() {
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "hi".to_string(),
    }])
    .await;

    let out = barry()
        .args(["-p", "hi", "--json"])
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let events: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON line {line:?}: {e}"))
        })
        .collect();

    assert!(!events.is_empty(), "expected at least one event");
    assert!(
        events.iter().any(|e| e.get("TextDelta").is_some()),
        "expected a TextDelta event: {events:?}"
    );

    let last = events.last().expect("at least one event");
    assert!(
        last.get("TurnFinished").is_some(),
        "the last line must be TurnFinished: {last}"
    );
    assert_eq!(
        last["TurnFinished"]["stop"], "Stop",
        "a completed turn stops: {last}"
    );
}
