//! BC-6.6 After compaction the session log still contains the original
//! messages, plus a `compaction` entry.
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
async fn bc_6_6_compaction_writes_a_compaction_log_entry() {
    // context_window = 20000 -> threshold = 3616 estimated tokens (~14.5 KB).
    // A 20 KB user message exceeds the threshold at turn start, so compaction
    // runs and summarises before any tool is called.
    let config = Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: 20_000,
        sandbox_network: true,
        fs_read_deny: vec![],
        fs_protected: vec![],
        hooks: vec![],
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    let log_path = log.path().to_path_buf();

    let provider = Arc::new(RecordingProvider::new(vec![
        // Reply 1: the summarisation request.
        done_text("the summary"),
        // Reply 2: the actual turn after compaction.
        done_text("final answer"),
    ]));

    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs")
        .with_session_log(log);

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn(&"x".repeat(20_000), tx, CancellationToken::new())
        .await
        .expect("turn completes");

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
    // removed_seq_range covers the messages that were compacted away.
    assert!(compaction["removed_seq_range"].is_array());
    // The raw user message is still in the log (session log is append-only).
    assert!(
        log_text.contains("\"type\":\"message\""),
        "raw messages stay in the log: {log_text}"
    );
}
