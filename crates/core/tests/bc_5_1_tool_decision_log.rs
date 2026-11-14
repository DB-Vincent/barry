/// BC-5.1 Every tool call produces a `tool_decision` entry recording who
/// decided (rule id, user or hook) and a `tool_result` entry.
use barry_core::config::Config;
use barry_core::session::SessionLog;
use barry_core::Agent;
use barry_policy::{BashRule, Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, Decision};
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
    policy_with_rules(ws, vec![])
}

fn policy_with_rules(ws: &Workspace, rules: Vec<BashRule>) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules,
        network: true,
    })
    .expect("policy constructs")
}

fn entries(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("read session log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid log line"))
        .collect()
}

#[tokio::test]
async fn bc_5_1_tool_call_logs_decision_and_result() {
    let ws = Workspace::new();
    let target = ws.outside().join("f");

    // A write outside cwd asks, and the user approves it once.
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalChoice::Once]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({ "path": target, "content": "hi" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let mut agent = Agent::new(
        config(),
        provider.clone(),
        approver.clone(),
        Some(policy(&ws)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write a file", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let entries = entries(&log_path);

    let decision = entries
        .iter()
        .find(|e| e["type"] == "tool_decision")
        .expect("a tool_decision entry");
    assert_eq!(decision["tool"], "write");
    assert_eq!(decision["decision"], "allow");
    assert_eq!(
        decision["decided_by"], "user",
        "the user approved the write: {decision}"
    );

    let result = entries
        .iter()
        .find(|e| e["type"] == "tool_result")
        .expect("a tool_result entry");
    assert_eq!(result["ok"], true);
    assert_eq!(result["call_id"], decision["call_id"]);
    assert!(
        result["bytes"].as_u64().unwrap_or(0) > 0,
        "the result records its size: {result}"
    );

    assert!(
        entries.iter().any(|e| e["type"] == "grant"),
        "the approved directory is logged as a grant"
    );
}

/// BC-5.1 A command allowed by a configured rule records that rule as the
/// decider.
#[tokio::test]
async fn bc_5_1_rule_decided_call_records_the_rule_id() {
    let ws = Workspace::new();
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "echo hi" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let rules = vec![BashRule {
        id: "allow-echo".to_string(),
        r#match: "echo hi".to_string(),
        decision: Decision::Allow,
    }];
    let mut agent = Agent::new(
        config(),
        provider,
        Arc::new(ScriptedApprover::none()),
        Some(policy_with_rules(&ws, rules)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("say hi", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let entries = entries(&log_path);
    let decision = entries
        .iter()
        .find(|e| e["type"] == "tool_decision")
        .expect("a tool_decision entry");
    assert_eq!(decision["decision"], "allow");
    assert_eq!(decision["decided_by"], "rule:allow-echo");
}

/// BC-5.1 A command allowed by an earlier "always this session" approval
/// records the user, not the synthetic policy grant label.
#[tokio::test]
async fn bc_5_1_session_granted_call_records_the_user() {
    let ws = Workspace::new();
    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::AlwaysThisSession,
    ]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "npm install foo" }),
        },
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "npm install bar" }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    // Force the first call to ask regardless of the default allow list, so the
    // only way the second call proceeds is the session prefix grant.
    let rules = vec![BashRule {
        id: "ask-npm".to_string(),
        r#match: "npm install foo".to_string(),
        decision: Decision::Ask {
            reason: "installing packages".to_string(),
        },
    }];
    let mut agent = Agent::new(
        config(),
        provider,
        approver,
        Some(policy_with_rules(&ws, rules)),
    )
    .expect("agent constructs")
    .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("install the packages", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let entries = entries(&log_path);
    let decisions: Vec<_> = entries
        .iter()
        .filter(|e| e["type"] == "tool_decision")
        .collect();
    assert_eq!(decisions.len(), 2, "one decision per call: {entries:?}");
    for decision in &decisions {
        assert_eq!(
            decision["decided_by"], "user",
            "the session grant is a user decision: {decision}"
        );
    }
    assert!(
        entries
            .iter()
            .any(|e| e["type"] == "prefix_approved" && e["prefix"] == "npm"),
        "the approved prefix is logged: {entries:?}"
    );
}
