/// BC-4.5 Writing `.git/config` from bash fails inside the sandbox unless
/// `.git` has been granted.
use barry_core::config::Config;
use barry_core::Agent;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, StopReason};
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
        sandbox_network: true,
        fs_read_deny: vec![],
        fs_protected: vec![".git".to_string()],
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

fn bash(command: &str) -> Reply {
    Reply::Tool {
        name: "bash".to_string(),
        arguments: json!({ "command": command }),
    }
}

async fn run(ws: &Workspace, approver: Arc<ScriptedApprover>) -> String {
    let provider = Arc::new(ScriptedProvider::new(vec![
        bash("echo x > .git/config"),
        Reply::Text {
            content: "done".to_string(),
        },
    ]));
    let mut agent = Agent::new(config(), provider.clone(), approver, Some(policy(ws)))
        .expect("agent constructs");
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write .git/config", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop);
    std::fs::read_to_string(ws.cwd().join(".git/config")).expect("read .git/config")
}

#[tokio::test]
async fn bc_4_5_git_config_blocked_without_grant() {
    let ws = Workspace::new();
    let original = std::fs::read_to_string(ws.cwd().join(".git/config")).expect("original config");

    // Approve the command once, then deny the `.git` grant: the sandbox
    // protection must stand and the original failure reaches the model.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let after = run(&ws, approver.clone()).await;

    assert_eq!(
        after, original,
        ".git/config must be untouched without a grant"
    );
    assert_eq!(approver.asked().len(), 2, "approver consulted twice");
    assert_eq!(
        approver.asked()[1].grant_path.as_deref(),
        Some(std::path::Path::new(".git")),
        "the grant offered is for .git"
    );
}

#[tokio::test]
async fn bc_4_5_git_config_writable_after_grant() {
    let ws = Workspace::new();

    // Approve the command, then approve the `.git` grant: the grant overrides
    // the read-only mount and the write succeeds.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Once,
    ]));
    let after = run(&ws, approver.clone()).await;

    assert_eq!(after, "x\n", ".git/config is writable after a grant");
    assert_eq!(approver.asked().len(), 2, "approver consulted twice");
}
