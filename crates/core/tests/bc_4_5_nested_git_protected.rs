//! BC-4.5 for nested repositories (issue #16): writing a submodule's
//! `.git/config` from bash fails inside the sandbox unless that `.git` has been
//! granted. The top-level `.git` alone is not enough.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::Agent;
use barry_core::config::Config;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, StopReason};
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const NESTED: &str = "vendor/lib/.git";

fn config() -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        context_window: 32_768,
        sandbox_network: true,
        sandbox_unsandboxed: false,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![".git".to_string()],
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
        protected: vec![".git".to_string()],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

async fn run(ws: &Workspace, approver: Arc<ScriptedApprover>) -> String {
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": format!("echo x > {NESTED}/config") }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));
    let mut agent = Agent::new(config(), provider, approver, policy(ws)).expect("agent constructs");
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write the submodule config", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop);
    std::fs::read_to_string(ws.cwd().join(NESTED).join("config")).expect("read nested config")
}

fn seed(ws: &Workspace) {
    let dir = ws.cwd().join(NESTED);
    std::fs::create_dir_all(&dir).expect("nested .git");
    std::fs::write(dir.join("config"), "[core]\n").expect("nested config");
}

#[tokio::test]
async fn nested_git_config_blocked_without_grant() {
    let ws = Workspace::new();
    seed(&ws);

    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let after = run(&ws, approver.clone()).await;

    assert_eq!(
        after, "[core]\n",
        "a nested .git/config must be untouched without a grant"
    );
    assert_eq!(
        approver.asked()[1].grant_path.as_deref(),
        Some(std::path::Path::new(NESTED)),
        "the grant offered is for the nested .git"
    );
}

#[tokio::test]
async fn nested_git_config_writable_after_grant() {
    let ws = Workspace::new();
    seed(&ws);

    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Once,
    ]));
    let after = run(&ws, approver.clone()).await;

    assert_eq!(after, "x\n", "a granted nested .git is writable");
    assert_eq!(approver.asked().len(), 2, "approver consulted twice");
}
