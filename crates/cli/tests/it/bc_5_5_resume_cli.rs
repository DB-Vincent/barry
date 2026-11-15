//! BC-5.5 `barry --resume <file>` sends the earlier conversation in the first
//! request to the model.
use barry_core::session::{EntryKind, SessionLog};
use barry_protocol::Message;
use barry_testkit::{FakeLlm, Reply};

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
async fn bc_5_5_resume_carries_the_earlier_conversation() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write a session log by hand: one question and one answer.
    let mut log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    log.append(EntryKind::Message {
        message: Message::User {
            content: "first question".to_string(),
        },
    })
    .expect("append user message");
    log.append(EntryKind::Message {
        message: Message::Assistant {
            content: Some("first answer".to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
    })
    .expect("append assistant message");
    let path = log.path().to_path_buf();
    drop(log);

    let llm = FakeLlm::start(vec![Reply::Text {
        content: "second answer".to_string(),
    }])
    .await;

    let out = barry()
        .args(["-p", "second question", "--resume"])
        .arg(&path)
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

    let requests = llm.requests();
    let first = requests.first().expect("a request after resume");
    let rendered = first.to_string();
    assert!(
        rendered.contains("first question"),
        "the earlier user message is in the request: {rendered}"
    );
    assert!(
        rendered.contains("first answer"),
        "the earlier assistant message is in the request: {rendered}"
    );
}
