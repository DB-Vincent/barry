/// BC-4.2 When a bash write is denied by the sandbox, the user is offered a
/// grant for that directory. After approval the command is retried and
/// succeeds. After denial the original failure goes to the model.
use barry_core::config::Config;
use barry_core::Agent;
use barry_llm::LlmRequest;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, Message, StopReason};
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

fn bash(command: &str) -> Reply {
    Reply::Tool {
        name: "bash".to_string(),
        arguments: json!({ "command": command }),
    }
}

/// The last tool result the model received: `(ok, content)`.
fn last_tool_result(requests: &[LlmRequest]) -> (bool, String) {
    let req = requests.last().expect("at least one request");
    let msg = req
        .messages
        .iter()
        .rev()
        .find(|m| matches!(m, Message::Tool { .. }))
        .expect("a tool message");
    match msg {
        Message::Tool { content, ok, .. } => (*ok, content.clone()),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn bc_4_2_sandbox_denial_grant_then_retry() {
    let ws = Workspace::new();
    let target = ws.outside().join("f");

    // Two approvals: first for the `echo` command (Ask → Once), second for
    // the directory grant offered after the sandbox blocks the write.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Once,
    ]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        bash(&format!("echo x > {}", target.display())),
        Reply::Text {
            content: "written after grant".to_string(),
        },
    ]));

    let mut agent = Agent::new(
        config(),
        provider.clone(),
        approver.clone(),
        Some(policy(&ws)),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write outside", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop);

    assert!(
        target.exists(),
        "sandbox-denied write should succeed after grant: {target:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read file"),
        "x\n",
        "file content should match"
    );

    // One approval for the command, one for the grant.
    assert_eq!(approver.asked().len(), 2, "approver consulted twice");
    assert!(
        approver.asked()[1].grant_path.is_some(),
        "the second request offers a directory grant"
    );
}

#[tokio::test]
async fn bc_4_2_sandbox_denial_deny_sends_original_failure() {
    let ws = Workspace::new();
    let target = ws.outside().join("f");

    // Approve the command once, then deny the grant. The original sandbox
    // failure must reach the model.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        bash(&format!("echo x > {}", target.display())),
        Reply::Text {
            content: "could not write".to_string(),
        },
    ]));

    let mut agent = Agent::new(
        config(),
        provider.clone(),
        approver.clone(),
        Some(policy(&ws)),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write outside", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop);

    assert!(
        !target.exists(),
        "file must not be written when the grant is denied"
    );

    let (ok, content) = last_tool_result(&provider.seen_requests());
    assert!(!ok, "the model sees a failed tool result: {content}");
    assert!(
        content.contains("Read-only file system")
            || content.contains("Permission denied")
            || content.contains("Operation not permitted"),
        "the model receives the original sandbox failure, got: {content}"
    );

    assert_eq!(approver.asked().len(), 2, "approver consulted twice");
}
