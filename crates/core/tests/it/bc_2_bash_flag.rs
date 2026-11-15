#![allow(clippy::unwrap_used, clippy::expect_used)]

/// M4 bash runs inside the OS sandbox when a policy is configured, and
/// unsandboxed when no policy is present. The sandbox helper re-executes the
/// barry binary, so sandboxed execution is tested via integration tests
/// against the built binary; unit tests here cover the unsandboxed path and
/// the policy decision layer.
use barry_core::config::Config;
use barry_core::session::SessionLog;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_policy::{Decision, Policy, PolicyConfig};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

struct RecordingProvider {
    replies: Mutex<VecDeque<LlmEvent>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl RecordingProvider {
    fn new(replies: Vec<LlmEvent>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl barry_llm::Provider for RecordingProvider {
    fn stream(
        &self,
        req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
        self.requests.lock().unwrap().push(req);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("no more replies");
        stream::iter(vec![Ok(reply)]).boxed()
    }
}

struct LocalApprover;
impl Approver for LocalApprover {
    fn decide(
        &self,
        _req: &barry_protocol::ApprovalRequest,
    ) -> BoxFuture<'_, barry_protocol::ApprovalChoice> {
        Box::pin(async { barry_protocol::ApprovalChoice::Once })
    }
}

fn done_bash(command: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "bash".to_string(),
                arguments: json!({ "command": command }),
            }],
        },
        stop: StopReason::ToolCalls,
        usage: None,
    }
}

fn done_text(text: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: Some(text.to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
        stop: StopReason::Stop,
        usage: None,
    }
}

async fn collect_events(mut rx: mpsc::Receiver<Event>) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = rx.next().await {
        events.push(event);
    }
    events
}

/// Runs one bash tool call and returns the stop reason, the events and every
/// request the provider was handed.
async fn run_once(command: &str, policy: Policy) -> (StopReason, Vec<Event>, Vec<LlmRequest>) {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_bash(command),
        LlmEvent::TextDelta("ok".to_string()),
        done_text("ok"),
    ]));
    let approver = Arc::new(LocalApprover);
    let mut agent =
        Agent::new(config(true), provider.clone(), approver, policy).expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("go", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let events = collect_events(rx).await;
    let requests = provider.requests.lock().unwrap().clone();
    (stop, events, requests)
}

fn tool_content(requests: &[LlmRequest]) -> Option<String> {
    requests
        .iter()
        .flat_map(|req| req.messages.iter())
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
}

#[tokio::test]
async fn bc_4_bash_runs_unsandboxed_when_configured() {
    // #30: running without the sandbox is a config flag, not a missing policy.
    let (stop, events, _requests) = run_once("echo hello", permissive_policy()).await;

    assert_eq!(stop, StopReason::Stop);

    let ran = events
        .iter()
        .any(|e| matches!(e, Event::ToolFinished { ok: true, .. }));
    assert!(ran, "expected a successful bash call: {events:?}");
}

#[tokio::test]
async fn bc_4_bash_policy_deny_blocks_command() {
    // A bash deny rule blocks the command regardless of sandbox.
    let policy = Policy::new(PolicyConfig {
        cwd: std::env::temp_dir().join("barry-test-bash-cwd2"),
        home: std::env::temp_dir().join("barry-test-bash-home2"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![barry_policy::BashRule {
            id: "no-echo".to_string(),
            r#match: "echo hello".to_string(),
            decision: Decision::Deny {
                reason: "echo is blocked".to_string(),
            },
        }],
        network: true,
    })
    .expect("policy constructs");

    let (stop, events, requests) = run_once("echo hello", policy).await;

    assert_eq!(stop, StopReason::Stop);

    let denied = events.iter().any(|e| {
        matches!(
            e,
            Event::ToolFinished { ok: false, display, .. }
                if display.contains("bash denied")
        )
    });
    assert!(denied, "expected bash to be denied: {events:?}");

    let content = tool_content(&requests).expect("a request carries the tool result");
    assert!(
        content.contains("bash denied"),
        "expected deny message: {content}"
    );
    assert!(
        !content.contains("hello"),
        "the command must not have run: {content}"
    );
}

/// A policy with no rules and no read-deny, for tests that cover the turn loop
/// and the tool plumbing rather than the policy engine (#30). It pre-approves
/// nothing: a write outside its own cwd goes to the test approver.
fn permissive_policy() -> barry_policy::Policy {
    barry_policy::Policy::new(barry_policy::PolicyConfig {
        cwd: std::env::temp_dir().join("barry-test-policy-cwd"),
        home: std::env::temp_dir().join("barry-test-policy-home"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

fn config(unsandboxed: bool) -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        context_window: 32_768,
        sandbox_network: true,
        sandbox_unsandboxed: unsandboxed,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
        budgets: barry_core::budget::Budgets::default(),
    }
}

/// #30: running without the OS sandbox is a decision, so the audit trail names
/// it; with the flag off, nothing claims the sandbox was disabled.
#[tokio::test]
async fn bc_4_unsandboxed_mode_is_logged() {
    for (unsandboxed, expected) in [(true, true), (false, false)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SessionLog::create_in(dir.path(), "main").expect("session log");
        let log_path = log.path().to_path_buf();
        let provider = Arc::new(RecordingProvider::new(vec![done_text("ok")]));
        let _agent = Agent::new(
            config(unsandboxed),
            provider,
            Arc::new(LocalApprover),
            permissive_policy(),
        )
        .expect("agent constructs")
        .with_session_log(log);

        let content = std::fs::read_to_string(&log_path).expect("read session log");
        assert!(content.contains("\"session_start\""));
        assert_eq!(
            content.contains("sandbox disabled by config"),
            expected,
            "unsandboxed={unsandboxed}: {content}"
        );
    }
}
