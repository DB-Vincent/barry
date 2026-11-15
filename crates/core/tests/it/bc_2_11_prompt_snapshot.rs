#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    unsafe_code,
    reason = "Rust 2024 makes env::set_var unsafe; the tests that use it do not share the variable across threads"
)]

/// BC-2.11 The tool list sent to the model contains exactly
/// `read, write, edit, bash` — the agent tool stays hidden until sub-agents
/// exist (#33) — and the system prompt matches the approved snapshot (insta).
///
/// The prompt is checked through the wire-shaped `LlmRequest` rather than by
/// calling the builder directly, so the snapshot covers what the model really
/// receives. The cwd and date are session facts, so they are normalised before
/// snapshotting; the rest is the approved PLAN 5.2 template.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::HOME_LOCK;

use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
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

fn done_read_call(path: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "read".to_string(),
                arguments: json!({ "path": path }),
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

#[tokio::test]
async fn bc_2_11_tool_list_is_exact_and_prompt_matches_snapshot() {
    let fixture = tempfile::tempdir().unwrap();
    let note = fixture.path().join("note.txt");
    std::fs::write(&note, "hi\n").unwrap();
    let provider = Arc::new(RecordingProvider::new(vec![
        done_read_call(note.to_str().unwrap()),
        LlmEvent::TextDelta("ok".to_string()),
        done_text("ok"),
    ]));
    // Keep HOME pointing at an empty dir so no AGENTS.md/skills leak into the
    // prompt and the snapshot stays stable across machines (PLAN 6.3).
    let home = tempfile::tempdir().unwrap();
    let mut agent = {
        let _guard = HOME_LOCK.lock().unwrap();
        // SAFETY: test-only; no other thread reads or writes the environment here.
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let agent = Agent::new(
            Config {
                default_model: "test".to_string(),
                max_turns: 10,
                context_window: 32_768,
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
            Arc::new(LocalApprover),
            permissive_policy(),
        )
        .expect("agent constructs");
        // SAFETY: test-only; no other thread reads or writes the environment here.
        unsafe {
            std::env::remove_var("HOME");
        }
        agent
    };

    let (tx, rx) = mpsc::channel(32);
    agent
        .run_turn("look around", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    let _ = collect_events(rx).await;

    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");

    // Exactly these tools, in this order (PLAN 5.1 plus the read-only search tools).
    let names: Vec<&str> = requests[0]
        .tools
        .iter()
        .map(|spec| spec.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["read", "glob", "grep", "ls", "write", "edit", "bash"]
    );

    let system_of = |index: usize| -> String {
        match &requests[index].messages[0] {
            Message::System { content } => content.clone(),
            other => panic!("expected a system message first, got {other:?}"),
        }
    };
    let first = system_of(0);
    let second = system_of(1);

    // PLAN 5.2: byte-identical across turns so providers can cache the prefix.
    assert_eq!(
        first, second,
        "the system prompt must not change between turns"
    );

    let cwd = std::env::current_dir().expect("cwd").display().to_string();
    let date = barry_core::testing::today();
    let mut normalized = first
        .replace(&cwd, "[CWD]")
        .replace(&date, "[DATE]")
        .replace(std::env::consts::OS, "[OS]");
    // PLAN 6.3: the AGENTS.md/skills instructions section depends on the
    // filesystem (git root AGENTS.md, ~/.config/barry/AGENTS.md, skills dirs),
    // so it is not deterministic for this snapshot test. It is covered
    // separately by BC-6.1 to BC-6.3. Strip it here so the snapshot captures
    // only the PLAN 5.2 template.
    if let Some(pos) = normalized.find("\n# Project instructions") {
        normalized.truncate(pos);
    }
    insta::assert_snapshot!(normalized);
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
