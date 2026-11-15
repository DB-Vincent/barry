//! #28 The agent works from the directory it was built for, not from whatever
//! the process happens to be in.
//!
//! Two agents in one process used to share `std::env::current_dir()`, and a
//! PreToolUse hook was told the process cwd rather than the agent's. Both are
//! observable: the request the model receives names its workspace, and the
//! hook payload carries the cwd.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::Agent;
use barry_core::config::{Config, HookConfig};
use barry_llm::LlmRequest;
use barry_policy::{Policy, PolicyConfig};
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

fn agent_for(ws: &Workspace, provider: Arc<ScriptedProvider>, cfg: Config) -> Agent {
    Agent::with_paths(
        cfg,
        provider,
        Arc::new(ScriptedApprover::none()),
        policy(ws),
        ws.cwd().to_path_buf(),
        ws.home().to_path_buf(),
    )
    .expect("agent constructs")
}

/// Everything the model saw, as one string.
fn request_text(req: &LlmRequest) -> String {
    req.messages
        .iter()
        .map(|m| format!("{m:?}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn bc_2_13_two_agents_keep_their_own_cwd() {
    let first = Workspace::new();
    let second = Workspace::new();

    let first_provider = Arc::new(ScriptedProvider::new(vec![Reply::Text {
        content: "one".to_string(),
    }]));
    let second_provider = Arc::new(ScriptedProvider::new(vec![Reply::Text {
        content: "two".to_string(),
    }]));

    let mut first_agent = agent_for(&first, first_provider.clone(), config());
    let mut second_agent = agent_for(&second, second_provider.clone(), config());

    let (tx1, _rx1) = mpsc::channel(32);
    first_agent
        .run_turn("hello", tx1, CancellationToken::new())
        .await
        .expect("first turn");
    let (tx2, _rx2) = mpsc::channel(32);
    second_agent
        .run_turn("hello", tx2, CancellationToken::new())
        .await
        .expect("second turn");

    let first_text = request_text(first_provider.seen_requests().first().expect("request"));
    let second_text = request_text(second_provider.seen_requests().first().expect("request"));

    assert!(
        first_text.contains(&first.cwd().display().to_string()),
        "the first agent's prompt names its own workspace"
    );
    assert!(
        !first_text.contains(&second.cwd().display().to_string()),
        "and not the other agent's"
    );
    assert!(
        second_text.contains(&second.cwd().display().to_string()),
        "the second agent's prompt names its own workspace"
    );
}

#[tokio::test]
async fn bc_2_13_hooks_receive_the_agents_cwd() {
    let ws = Workspace::new();
    std::fs::write(ws.file("target.txt"), "content").expect("write target");

    // The hook records the payload it was given on stdin.
    let capture = ws.file("hook-payload.json");
    let script = ws.file("hook.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ncat > '{}'\nexit 0\n", capture.display()),
    )
    .expect("write hook script");

    let mut cfg = config();
    cfg.hooks = vec![HookConfig {
        matcher: "read".to_string(),
        command: vec!["/bin/sh".to_string(), script.display().to_string()],
        timeout_secs: 10,
        fail_closed: true,
    }];

    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "read".to_string(),
            arguments: json!({ "path": ws.file("target.txt").display().to_string() }),
        },
        Reply::Text {
            content: "read it".to_string(),
        },
    ]));

    let mut agent = agent_for(&ws, provider, cfg);
    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("read the file", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let payload = std::fs::read_to_string(&capture).expect("hook payload");
    assert!(
        payload.contains("\"PreToolUse\""),
        "the hook received a payload: {payload}"
    );
    assert!(
        payload.contains(&format!("\"cwd\":\"{}\"", ws.cwd().display())),
        "the payload names the agent's cwd, not the process's: {payload}"
    );
}
