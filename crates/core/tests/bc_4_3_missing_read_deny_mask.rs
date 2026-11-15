//! Issue #16: a read-deny path that does not exist when the session starts is
//! still masked. Bash writes into the tmpfs mask instead of the real directory,
//! so nothing appears on the host.
//!
//! This is a Linux guarantee: bubblewrap mounts a tmpfs over the missing path.
//! Seatbelt resolves path filters when the profile is compiled, so a path that
//! does not exist yet cannot be denied there, and macOS protects an existing
//! read-deny entry instead.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::Agent;
use barry_core::config::Config;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::ApprovalChoice;
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
        sandbox_network: true,
        sandbox_unsandboxed: false,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    }
}

#[tokio::test]
async fn missing_read_deny_path_is_masked() {
    let ws = Workspace::new();
    let hidden = ws.cwd().join("new-secret");

    // The entry does not exist yet: no credentials are on disk at startup.
    let policy = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![hidden.display().to_string()],
        protected: vec![],
        rules: vec![],
        network: false,
    })
    .expect("policy constructs");

    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            // Relative target: the policy allows a write inside cwd, so only
            // the sandbox can stop it from landing on the host.
            arguments: json!({ "command": "mkdir -p new-secret && echo secret > new-secret/data" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalChoice::Once]));
    let mut agent =
        Agent::new(config(), provider.clone(), approver, policy).expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write the secret", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    assert!(
        !hidden.join("data").exists(),
        "writes to a missing read-deny path must stay inside the sandbox"
    );
}
