/// BC-4.1 `echo x > ../outside/f` run by bash does not create the file, even
/// though the rule layer asked and the user approved it "once" without a
/// grant. This proves the sandbox is a separate layer from policy.
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

#[tokio::test]
async fn bc_4_1_sandbox_blocks_outside_write_despite_approval() {
    let ws = Workspace::new();
    let target = ws.outside().join("f");

    let policy = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs");

    // The command itself is approved once; the directory grant offered after
    // the sandbox blocks it is denied. The write must still fail.
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": format!("echo x > {}", target.display()) }),
        },
        Reply::Text {
            content: "could not write".to_string(),
        },
    ]));

    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
        },
        provider,
        approver.clone(),
        Some(policy),
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
        "sandbox must block the write outside cwd even with user approval"
    );
    assert_eq!(
        approver.asked().len(),
        2,
        "the command was approved, then the grant was offered and denied"
    );
    assert!(
        approver.asked()[0].grant_path.is_none(),
        "the first request is the command itself, not a grant"
    );
}
