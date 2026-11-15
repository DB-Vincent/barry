//! BC-6.4 / #22 When compaction cannot reduce the context any further, the
//! turn stops with `ContextFull` instead of sending a request that overflows.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Event, Message, StopReason};
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
async fn bc_6_4_a_context_that_cannot_shrink_ends_the_turn() {
    // Threshold = 20,000 - 16,384 = 3,616 estimated tokens (~14.5 KB). A 20 KB
    // prompt is already over it at turn start, and there is nothing older than
    // the newest turns to summarise, so the request would overflow.
    let provider = Arc::new(RecordingProvider::new(vec![done_text("never sent")]));
    let mut agent = Agent::new(
        barry_core::config::Config {
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
            budgets: barry_core::budget::Budgets::default(),
        },
        provider.clone(),
        Arc::new(AlwaysAllow),
        permissive_policy(),
    )
    .expect("agent");

    let (tx, mut rx) = mpsc::channel(32);
    let stop = agent
        .run_turn(&"x".repeat(20_000), tx, CancellationToken::new())
        .await
        .expect("an overfull context is a stop, not an error");

    assert_eq!(stop, StopReason::ContextFull);
    assert!(
        provider.requests.lock().unwrap().is_empty(),
        "no request is sent that would overflow"
    );

    let mut notices = Vec::new();
    let mut finished = None;
    while let Some(event) = rx.next().await {
        match event {
            Event::Notice(text) => notices.push(text),
            Event::TurnFinished { stop, .. } => finished = Some(stop),
            _ => {}
        }
    }
    assert_eq!(notices, vec!["context full".to_string()], "one notice");
    assert_eq!(finished, Some(StopReason::ContextFull));
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
