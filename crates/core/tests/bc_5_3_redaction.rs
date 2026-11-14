/// BC-5.3 When a tool reads a file containing `sk-` followed by 30 chars, or
/// `FAKE` env secret values, the log shows `[REDACTED]`, never the secret.
/// The model still receives the real content.
use barry_core::config::Config;
use barry_core::session::SessionLog;
use barry_core::Agent;
use barry_policy::{Policy, PolicyConfig};
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const SECRET: &str = "sk-abcdefghijklmnopqrstuvwxyz0123";
const ENV_SECRET: &str = "FAKE-ENV-SECRET-VALUE-98765";

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
async fn bc_5_3_secrets_are_redacted_in_the_log_only() {
    // The redactor snapshots secret env values when the log is created.
    std::env::set_var("BARRY_TEST_SECRET_TOKEN", ENV_SECRET);

    let ws = Workspace::new();
    let contents = format!("api_key = {SECRET}\ntoken = {ENV_SECRET}\n");
    std::fs::write(ws.file("credentials.txt"), &contents).expect("write credentials");

    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "read".to_string(),
            arguments: json!({ "path": ws.file("credentials.txt").display().to_string() }),
        },
        Reply::Text {
            content: "read it".to_string(),
        },
    ]));

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let mut agent = Agent::new(
        config(),
        provider.clone(),
        Arc::new(ScriptedApprover::none()),
        Some(policy(&ws)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("read the credentials", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    std::env::remove_var("BARRY_TEST_SECRET_TOKEN");

    let log_text = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        log_text.contains("[REDACTED]"),
        "the log marks redacted values: {log_text}"
    );
    assert!(
        !log_text.contains(SECRET),
        "the sk- secret never appears in the log"
    );
    assert!(
        !log_text.contains(ENV_SECRET),
        "the env secret value never appears in the log"
    );

    // The model still gets the real file content.
    let requests = provider.seen_requests();
    let last = requests.last().expect("at least one request");
    let tool_content = last
        .messages
        .iter()
        .rev()
        .find_map(|m| match m {
            barry_protocol::Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a tool result");
    assert!(
        tool_content.contains(SECRET),
        "the model receives the real secret: {tool_content}"
    );
}

/// BC-5.3 Every pattern listed in PLAN 6.7 is redacted, not just `sk-`.
#[test]
fn bc_5_3_built_in_secret_patterns_are_redacted() {
    let redactor = barry_core::redact::Redactor::new(vec![]);
    let secrets = [
        "ghp_123456789012345678901234567890123456",
        "AKIA1234567890ABCDEF",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
    ];

    for secret in secrets {
        let redacted = redactor.redact(&format!("before {secret} after"));
        assert!(
            !redacted.contains(secret),
            "the secret is removed: {redacted}"
        );
        assert!(
            redacted.contains("[REDACTED]"),
            "the redaction marker is present: {redacted}"
        );
    }
}

/// BC-5.3 Redaction applies to `tool_decision` input too, and never to the
/// file the tool actually writes.
#[tokio::test]
async fn bc_5_3_tool_decision_input_is_redacted() {
    let ws = Workspace::new();
    let target = ws.file("written.txt");
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({ "path": target, "content": SECRET }),
        },
        Reply::Text {
            content: "wrote it".to_string(),
        },
    ]));

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let mut agent = Agent::new(
        config(),
        provider,
        Arc::new(ScriptedApprover::none()),
        Some(policy(&ws)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write the secret", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let log_text = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        !log_text.contains(SECRET),
        "the tool input is redacted in the log: {log_text}"
    );
    assert!(
        log_text.contains("[REDACTED]"),
        "the log marks the redaction: {log_text}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read written file"),
        SECRET,
        "the write itself is not redacted"
    );
}
