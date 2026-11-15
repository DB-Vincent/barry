//! BC-6.6 After compaction the session log still contains the original
//! messages, plus a `compaction` entry describing what was replaced.
use barry_core::config::Config;
use barry_core::session::SessionLog;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Message, StopReason, ToolCall};
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

fn done_tool(name: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: name.to_string(),
                arguments,
            }],
        },
        stop: StopReason::ToolCalls,
        usage: None,
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
async fn bc_6_6_compaction_writes_a_compaction_log_entry() {
    // context_window = 30,000 -> threshold = 13,616 estimated tokens (~54 KB).
    // Three 20 KB tool outputs stay under it; the fourth turn's request is the
    // first one over, which is when compaction summarises the oldest turns.
    let config = Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: 30_000,
        sandbox_network: true,
        sandbox_unsandboxed: true,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool(
            "bash",
            json!({ "command": "head -c 20000 /dev/zero | tr '\\0' 'a'" }),
        ),
        done_text("first done"),
        done_tool(
            "bash",
            json!({ "command": "head -c 20000 /dev/zero | tr '\\0' 'b'" }),
        ),
        done_text("second done"),
        done_tool(
            "bash",
            json!({ "command": "head -c 20000 /dev/zero | tr '\\0' 'c'" }),
        ),
        // Turn three's second request is the first one over the threshold, so
        // it is preceded by the summarisation request.
        done_text("the summary"),
        done_text("third done"),
        done_text("fourth done"),
    ]));

    let mut agent = Agent::new(
        config,
        provider.clone(),
        Arc::new(AlwaysAllow),
        permissive_policy(),
    )
    .expect("agent constructs")
    .with_session_log(log);

    for prompt in ["first request", "second request", "third request"] {
        let (tx, _rx) = mpsc::channel(32);
        agent
            .run_turn(prompt, tx, CancellationToken::new())
            .await
            .expect("turn completes");
    }
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("fourth request", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop, "compaction let the turn continue");

    let log_text = std::fs::read_to_string(&log_path).expect("read session log");
    let entries: Vec<serde_json::Value> = log_text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("valid log line"))
        .collect();

    let compaction = entries.iter().find(|e| e["type"] == "compaction");
    assert!(
        compaction.is_some(),
        "expected a compaction log entry in: {log_text}"
    );
    let compaction = compaction.unwrap();
    assert_eq!(compaction["summary"], "the summary");
    // removed_seq_range covers the messages that were compacted away, and it
    // stops before the turns that were kept.
    let range = compaction["removed_seq_range"]
        .as_array()
        .expect("removed_seq_range is an array");
    assert_eq!(range.len(), 2);
    assert_eq!(range[0], 0);
    let removed = range[1].as_u64().expect("an end index");
    assert!(removed > 0, "something was compacted: {compaction}");

    // The raw messages are still in the log (the session log is append-only).
    assert!(
        log_text.contains("\"type\":\"message\"") && log_text.contains("first request"),
        "raw messages stay in the log: {log_text:.400}"
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
