/// BC-2.5 / #19 Neither `read` nor `bash` buffers more output than it can show.
///
/// A file larger than the read window comes back as numbered head + marker +
/// numbered tail without reading the whole file, a file above the hard limit is
/// refused, and a command that never stops printing is killed once it passes
/// the capture limit instead of growing the buffer until the timeout.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

struct LocalProvider {
    replies: Mutex<VecDeque<LlmEvent>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl LocalProvider {
    fn new(replies: Vec<LlmEvent>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl barry_llm::Provider for LocalProvider {
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

fn done_call(tool: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: tool.to_string(),
                arguments,
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

/// The tool's own summary, ok flag, and the text the model was handed.
struct Run {
    ok: bool,
    display: String,
    model: String,
}

/// Run one tool call through a real agent turn.
async fn run_tool(tool: &str, arguments: serde_json::Value) -> Run {
    let provider = Arc::new(LocalProvider::new(vec![
        done_call(tool, arguments),
        LlmEvent::TextDelta("done".to_string()),
        done_text("done"),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
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
        },
        provider.clone(),
        approver,
        permissive_policy(),
    )
    .expect("agent constructs");

    let (tx, mut rx) = mpsc::channel(32);
    agent
        .run_turn("do it", tx, CancellationToken::new())
        .await
        .expect("ok");

    let mut result = None;
    while let Some(event) = rx.next().await {
        if let Event::ToolFinished { ok, display, .. } = event {
            result = Some((ok, display));
        }
    }
    let (ok, display) = result.expect("a ToolFinished event");

    // The request sent after the tool result carries what the model saw.
    let model = provider
        .requests
        .lock()
        .unwrap()
        .iter()
        .flat_map(|req| req.messages.iter())
        .find_map(|message| match message {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a request carries the tool result");

    Run { ok, display, model }
}

#[tokio::test]
async fn read_of_a_large_file_returns_a_bounded_window() {
    let tmp = tempfile::tempdir().unwrap();
    let big = tmp.path().join("big.txt");
    // 40,000 two-byte lines: 80,000 bytes, past the whole-file read window.
    let body: String = (0..40_000).map(|_| "a\n").collect();
    std::fs::write(&big, &body).unwrap();

    let run = run_tool("read", json!({ "path": big.to_str().unwrap() })).await;

    assert!(run.ok, "large files still read: {:.120}", run.display);
    assert!(
        run.display.starts_with("1: a"),
        "head is numbered: {:.120}",
        run.display
    );
    assert!(
        run.display.trim_end().ends_with("40000: a"),
        "tail keeps the real line number: {:.120}",
        run.display
    );
    assert!(
        run.display.contains(" of 80000 bytes ...]"),
        "the skipped bytes are stated: {:.200}",
        run.display
    );
    assert!(
        run.display.len() < 60_000,
        "output stays at head+tail size, got {} bytes",
        run.display.len()
    );
    assert!(
        run.model.len() < 60_000,
        "the model is not handed the whole file: {} bytes",
        run.model.len()
    );
}

#[tokio::test]
async fn read_refuses_a_file_past_the_read_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let huge = tmp.path().join("huge.bin");
    // Sparse, so the test costs no disk: only the size matters.
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(17 * 1024 * 1024)
        .unwrap();

    let run = run_tool("read", json!({ "path": huge.to_str().unwrap() })).await;

    assert!(!run.ok, "oversized files are refused, not buffered");
    assert!(run.display.contains("read limit"), "{}", run.display);
}

#[tokio::test]
async fn endless_bash_output_is_killed_at_the_capture_limit() {
    let run = run_tool(
        "bash",
        json!({ "command": "yes barry", "timeout_secs": 30 }),
    )
    .await;

    assert!(
        !run.ok,
        "a killed command is not a success: {}",
        run.display
    );
    assert!(
        run.model.contains("output over") && run.model.contains("command killed"),
        "the model is told why the command stopped: {:.200}",
        run.model
    );
    assert!(
        run.model.len() < 100_000,
        "bounded output, got {} bytes",
        run.model.len()
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
