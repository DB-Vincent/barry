//! BC-6.7 `/compact` forces compaction of the conversation context (exercised
//! via `Agent::compact`, which the REPL `/compact` command calls).
use barry_core::config::Config;
use barry_core::session::SessionLog;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
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

impl Provider for RecordingProvider {
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

struct AlwaysAllow;
impl Approver for AlwaysAllow {
    fn decide(&self, _req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        Box::pin(async { ApprovalChoice::Once })
    }
}

fn done_text(content: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: Some(content.to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
        stop: StopReason::Stop,
        usage: None,
    }
}

#[tokio::test]
async fn bc_6_7_compact_forces_compaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let config = Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: 20_000,
        sandbox_network: true,
        sandbox_unsandboxed: true,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    };

    let provider = Arc::new(RecordingProvider::new(vec![
        // Reply 1: answer the seeded turn.
        done_text("previous answer"),
        // Reply 2: the summarisation request from compact().
        done_text("compacted summary"),
    ]));
    let mut agent = Agent::new(
        config,
        provider.clone(),
        Arc::new(AlwaysAllow),
        permissive_policy(),
    )
    .expect("agent constructs")
    .with_session_log(log);

    // Seed some history so there is something to compact.
    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("a previous turn", tx.clone(), CancellationToken::new())
        .await
        .expect("first turn");

    // Force compaction via /compact.
    let compacted = agent.compact().await.expect("compact runs");
    assert!(compacted, "compact should have performed a compaction");

    let log_text = std::fs::read_to_string(&log_path).expect("read session log");
    assert!(
        log_text.contains("\"type\":\"compaction\""),
        "compaction log entry written: {log_text}"
    );
}

#[tokio::test]
async fn bc_6_7_compact_nothing_to_compact() {
    let config = Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: 20_000,
        sandbox_network: true,
        sandbox_unsandboxed: true,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    };
    let mut agent = Agent::new(
        config,
        Arc::new(RecordingProvider::new(vec![])),
        Arc::new(AlwaysAllow),
        permissive_policy(),
    )
    .expect("agent constructs");

    // No session log and no history: nothing to compact.
    let result = agent.compact().await.expect("compact runs");
    assert!(!result, "empty history compacts to nothing");
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
