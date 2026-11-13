/// BC-2.9 Cancelling during a long bash command kills it. The history stays
/// valid: the next run_turn succeeds, and the model sees an "interrupted by
/// user" tool result.
use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Unique enough that `pgrep -f` cannot collide with another test's sleep.
const MARKER: &str = "sleep 100.987654";

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

fn marker_running() -> bool {
    // -f matches the full command line, -x requires it to match exactly.
    // Without -x, any process whose *arguments* merely mention the marker
    // (the shell that launched this test run, for instance) counts as a hit.
    std::process::Command::new("pgrep")
        .arg("-f")
        .arg("-x")
        .arg(MARKER)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn bc_2_9_cancel_during_bash_kills_it() {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_bash(&format!("exec {MARKER}")),
        done_text("carried on"),
    ]));
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: true,
        },
        provider.clone(),
        Arc::new(LocalApprover),
    )
    .expect("agent constructs");

    let cancel = CancellationToken::new();
    let turn_cancel = cancel.clone();
    let (tx, rx) = mpsc::channel(32);
    // run_turn takes &mut self, so hand the agent to the task and take it back.
    let handle = tokio::spawn(async move {
        let stop = agent.run_turn("run a long command", tx, turn_cancel).await;
        (stop, agent)
    });

    // Let bash actually start before pulling the plug.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let cancelled_at = std::time::Instant::now();
    cancel.cancel();

    let (stop, mut agent) = handle.await.expect("turn task joins");
    let elapsed = cancelled_at.elapsed();

    assert_eq!(
        stop.expect("a cancel is not an error"),
        StopReason::Aborted,
        "a cancelled turn returns Aborted"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "cancelling should not wait for the 120s timeout, took {elapsed:?}"
    );

    // The process must be gone, not merely abandoned.
    let mut gone = false;
    for _ in 0..20 {
        if !marker_running() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "the cancelled bash process is still running");

    let events = collect_events(rx).await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::ToolFinished { ok: false, display, .. } if display.contains("interrupted")
        )),
        "expected an interrupted tool result in this turn: {events:?}"
    );

    // The history must still be usable: exactly one Tool message per call id.
    let (tx2, rx2) = mpsc::channel(32);
    let stop2 = agent
        .run_turn("continue", tx2, CancellationToken::new())
        .await
        .expect("a second turn succeeds after a cancel");
    assert_eq!(stop2, StopReason::Stop);
    let _ = collect_events(rx2).await;

    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");

    let model_view = &requests[1].messages;
    let interrupted = model_view.iter().any(|m| {
        matches!(
            m,
            Message::Tool { content, tool_call_id, .. }
                if tool_call_id == "call_1" && content.contains("interrupted by user")
        )
    });
    assert!(
        interrupted,
        "the model must see the interrupted tool result: {model_view:?}"
    );
}
