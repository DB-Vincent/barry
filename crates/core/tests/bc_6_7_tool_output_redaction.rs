//! PLAN 6.7 / #17 Tool output can be redacted before it reaches the model.
//!
//! BC-5.3 keeps the default: the model gets the real tool output and only the
//! session log is redacted. With `redaction.tool_output = true` the model sees
//! `[REDACTED]` instead, which is what a remote provider needs.
use barry_core::config::Config;
use barry_core::Agent;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::Message;
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const SECRET: &str = "sk-abcdefghijklmnopqrstuvwxyz0123";

fn config(redact_tool_output: bool) -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        context_window: 32_768,
        sandbox_network: false,
        sandbox_unsandboxed: false,
        redact_tool_output,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
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
        network: false,
    })
    .expect("policy constructs")
}

/// Read a file containing a secret and return the tool content of the last
/// request the model received.
async fn tool_content_for(redact_tool_output: bool) -> String {
    let ws = Workspace::new();
    let file = ws.file("credentials.txt");
    std::fs::write(&file, format!("api_key = {SECRET}\n")).expect("write credentials");

    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "read".to_string(),
            arguments: json!({ "path": file.display().to_string() }),
        },
        Reply::Text {
            content: "read it".to_string(),
        },
    ]));

    let mut agent = Agent::new(
        config(redact_tool_output),
        provider.clone(),
        Arc::new(ScriptedApprover::none()),
        policy(&ws),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("read the credentials", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let requests = provider.seen_requests();
    let last = requests.last().expect("at least one request");
    last.messages
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a tool result")
}

#[tokio::test]
async fn bc_6_7_tool_output_reaches_the_model_by_default() {
    let content = tool_content_for(false).await;
    assert!(
        content.contains(SECRET),
        "BC-5.3: the default still sends real tool output: {content}"
    );
    assert!(
        !content.contains("[REDACTED]"),
        "nothing is masked when redaction is off: {content}"
    );
}

#[tokio::test]
async fn bc_6_7_tool_output_is_redacted_when_configured() {
    let content = tool_content_for(true).await;
    assert!(
        !content.contains(SECRET),
        "the secret never reaches a remote provider: {content}"
    );
    assert!(
        content.contains("[REDACTED]"),
        "the model is told a value was masked: {content}"
    );
    assert!(
        content.contains("<tool_output tool=\"read\""),
        "the wrapped envelope survives redaction: {content}"
    );
}
