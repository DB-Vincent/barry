/// M2 (PLAN line 617) bash is unsandboxed and must sit behind the hidden
/// `--dev-unsafe-bash` flag. Without it the tool is advertised but refuses to
/// run, and the model is told why. With it the command runs normally.
use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
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
async fn run_once(
    dev_unsafe_bash: bool,
    command: &str,
) -> (StopReason, Vec<Event>, Vec<LlmRequest>) {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_bash(command),
        LlmEvent::TextDelta("ok".to_string()),
        done_text("ok"),
    ]));
    let approver = Arc::new(LocalApprover);
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash,
        },
        provider.clone(),
        approver,
    )
    .expect("agent constructs");

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
async fn bc_2_bash_refused_without_dev_unsafe_bash() {
    let (stop, events, requests) = run_once(false, "echo PWNED").await;

    assert_eq!(stop, StopReason::Stop);

    let refused = events.iter().any(|e| {
        matches!(
            e,
            Event::ToolFinished { ok: false, display, .. } if display.contains("bash disabled")
        )
    });
    assert!(refused, "expected a refused bash call: {events:?}");

    // The model is told how to enable it, and never sees the output.
    let content = tool_content(&requests).expect("a request carries the tool result");
    assert!(
        content.contains("--dev-unsafe-bash"),
        "refusal should name the flag: {content}"
    );
    assert!(
        !content.contains("PWNED"),
        "the command must not have run: {content}"
    );
}

#[tokio::test]
async fn bc_2_bash_runs_with_dev_unsafe_bash() {
    let (stop, events, requests) = run_once(true, "echo hello").await;

    assert_eq!(stop, StopReason::Stop);

    let ran = events
        .iter()
        .any(|e| matches!(e, Event::ToolFinished { ok: true, .. }));
    assert!(ran, "expected a successful bash call: {events:?}");

    let content = tool_content(&requests).expect("a request carries the tool result");
    assert!(content.contains("hello"), "expected stdout: {content}");
}
