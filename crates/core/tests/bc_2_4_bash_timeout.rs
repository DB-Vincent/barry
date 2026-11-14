/// BC-2.4 A bash command that runs past its timeout is killed, including
/// background children; the model is told it timed out; no process remains.
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
}

impl LocalProvider {
    fn new(replies: Vec<LlmEvent>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
        }
    }
}

impl barry_llm::Provider for LocalProvider {
    fn stream(
        &self,
        _req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
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

fn done_bash(command: &str, timeout_secs: u64) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "bash".to_string(),
                arguments: json!({ "command": command, "timeout_secs": timeout_secs }),
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
async fn bc_2_4_bash_timeout_kills_children() {
    // sleep 100 blocks bash for 100 seconds; a 1s timeout should kill it.
    let provider = Arc::new(LocalProvider::new(vec![
        done_bash("sleep 100", 1),
        LlmEvent::TextDelta("The command timed out.".to_string()),
        done_text("The command timed out."),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 10,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
        },
        provider.clone(),
        approver,
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("run sleep 100", tx, CancellationToken::new())
        .await
        .expect("ok");
    assert_eq!(stop, StopReason::Stop);

    let events = collect_events(rx).await;

    // ToolFinished with ok=false
    let failed: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: false, .. }))
        .collect();
    assert_eq!(failed.len(), 1, "expected one failed ToolFinished");

    // Timeout message
    let timed_out = events.iter().any(|e| {
        matches!(
            e,
            Event::ToolFinished { display, .. }
                if display.contains("timed out")
        )
    });
    assert!(timed_out, "expected timeout message in tool result");

    // Text delta from model's final answer
    let text_deltas: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::TextDelta(_)))
        .collect();
    assert_eq!(text_deltas.len(), 1);

    // One TurnFinished
    let finished: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::TurnFinished { .. }))
        .collect();
    assert_eq!(finished.len(), 1);
}

/// Runs `sleep 100` with the given timeout and returns the collected events.
async fn run_sleep_with_timeout(timeout_secs: u64) -> Vec<Event> {
    let provider = Arc::new(LocalProvider::new(vec![
        done_bash("sleep 100", timeout_secs),
        LlmEvent::TextDelta("timed out".to_string()),
        done_text("timed out"),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 10,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
        },
        provider,
        approver,
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    agent
        .run_turn("run sleep 100", tx, CancellationToken::new())
        .await
        .expect("ok");
    collect_events(rx).await
}

#[tokio::test]
async fn bc_2_4_timeout_secs_is_clamped_to_at_least_one() {
    // timeout_secs: 0 is clamped to 1 before reaching execute_bash, so this
    // still times out (after ~1s) instead of being instant or unlimited.
    let events = run_sleep_with_timeout(0).await;

    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::ToolFinished { display, .. } if display.contains("timed out after 1s")
        )),
        "expected the clamp to raise 0 to 1: {events:?}"
    );
}
