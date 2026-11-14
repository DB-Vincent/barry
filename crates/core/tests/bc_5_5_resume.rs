/// BC-5.5 After `--resume`, the first request to the model contains the
/// earlier conversation.
use barry_core::config::Config;
use barry_core::session::{EntryKind, SessionLog};
use barry_core::Agent;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::Message;
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn config() -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        sandbox_network: true,
        fs_read_deny: vec![],
        fs_protected: vec![],
    }
}

fn policy(ws: &Workspace) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

#[tokio::test]
async fn bc_5_5_resume_sends_earlier_conversation() {
    let ws = Workspace::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    // First session: one question and one answer.
    let first_provider = Arc::new(ScriptedProvider::new(vec![Reply::Text {
        content: "first answer".to_string(),
    }]));
    let mut first = Agent::new(
        config(),
        first_provider,
        Arc::new(ScriptedApprover::none()),
        Some(policy(&ws)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    first
        .run_turn("first question", tx, CancellationToken::new())
        .await
        .expect("first turn completes");
    drop(first);

    // Second session: resume from the log and ask a new question.
    let second_provider = Arc::new(ScriptedProvider::new(vec![Reply::Text {
        content: "second answer".to_string(),
    }]));
    let mut resumed = Agent::resume(
        config(),
        second_provider.clone(),
        Arc::new(ScriptedApprover::none()),
        Some(policy(&ws)),
        &log_path,
    )
    .expect("resume constructs");

    let (tx, _rx) = mpsc::channel(32);
    resumed
        .run_turn("second question", tx, CancellationToken::new())
        .await
        .expect("second turn completes");

    let report = barry_core::session::verify(&log_path).expect("verify the resumed log");
    assert_eq!(
        report.broken_at, None,
        "continuing the chain after resume keeps it valid"
    );
    assert!(
        report.entries > 3,
        "the log contains both sessions' entries: {report:?}"
    );

    let requests = second_provider.seen_requests();
    let first_request = requests.first().expect("a request after resume");

    let has_user = first_request
        .messages
        .iter()
        .any(|m| matches!(m, Message::User { content } if content == "first question"));
    let has_assistant = first_request.messages.iter().any(|m| {
        matches!(
            m,
            Message::Assistant { content: Some(text), .. } if text == "first answer"
        )
    });

    assert!(
        has_user && has_assistant,
        "the resumed request carries the earlier conversation: {first_request:?}"
    );
}

/// BC-5.5 Resume must not extend a log whose hash chain is broken.
#[tokio::test]
async fn bc_5_5_resume_refuses_a_broken_log() {
    let ws = Workspace::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    log.append(EntryKind::Message {
        message: Message::User {
            content: "first question".to_string(),
        },
    })
    .expect("append user message");
    let log_path = log.path().to_path_buf();
    drop(log);

    let content = std::fs::read_to_string(&log_path).expect("read log");
    let tampered = content.replacen("first question", "first questioN", 1);
    std::fs::write(&log_path, tampered).expect("write tampered log");

    let err = Agent::resume(
        config(),
        Arc::new(ScriptedProvider::new(vec![])),
        Arc::new(ScriptedApprover::none()),
        Some(policy(&ws)),
        &log_path,
    )
    .err()
    .expect("resume refuses a broken chain");
    assert!(
        err.to_string().contains("broken at line"),
        "the error names the break: {err}"
    );
}
