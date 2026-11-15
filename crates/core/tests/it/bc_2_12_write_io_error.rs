//! #29 A filesystem failure is reported as an I/O error, not as a provider
//! error.
//!
//! The tool result is what the model sees, so the distinction is observable:
//! before this, writing under a path that is really a file said
//! "provider error", which reads as if the LLM endpoint had failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::Agent;
use barry_core::config::Config;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::Message;
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn config() -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        context_window: 32_768,
        sandbox_network: false,
        sandbox_unsandboxed: false,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
        budgets: barry_core::budget::Budgets::default(),
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

#[tokio::test]
async fn bc_29_write_error_is_reported_as_io() {
    let ws = Workspace::new();
    // `blocker` is a regular file, so writing `blocker/f` fails with ENOTDIR.
    let blocker = ws.file("blocker");
    std::fs::write(&blocker, "not a directory").expect("write blocker");
    let target = blocker.join("f");

    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({ "path": target, "content": "x" }),
        },
        Reply::Text {
            content: "could not write".to_string(),
        },
    ]));

    let mut agent = Agent::new(
        config(),
        provider.clone(),
        Arc::new(ScriptedApprover::none()),
        policy(&ws),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write it", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let requests = provider.seen_requests();
    let last = requests.last().expect("at least one request");
    let content = last
        .messages
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a tool result");

    assert!(
        content.contains("io error"),
        "the failure names its source: {content}"
    );
    assert!(
        !content.contains("provider error"),
        "an fs failure is not blamed on the provider: {content}"
    );
}
