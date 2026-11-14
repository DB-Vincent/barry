/// BC-2.6 A model that keeps calling tools stops after max_turns, and the
/// user gets a "turn limit reached" notice.
use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Replays a fixed number of tool-calling replies, then panics. If the loop
/// goes past max_turns the test fails loudly instead of hanging.
struct AlwaysToolProvider {
    calls: Mutex<usize>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl AlwaysToolProvider {
    fn new() -> Self {
        Self {
            calls: Mutex::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl barry_llm::Provider for AlwaysToolProvider {
    fn stream(
        &self,
        req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
        self.requests.lock().unwrap().push(req);

        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        let n = *calls;

        let reply = LlmEvent::Done {
            message: Message::Assistant {
                content: None,
                reasoning: None,
                tool_calls: vec![barry_protocol::ToolCall {
                    id: format!("call_{n}"),
                    name: "bash".to_string(),
                    arguments: json!({ "command": "echo again" }),
                }],
            },
            stop: StopReason::ToolCalls,
            usage: None,
        };
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

async fn collect_events(mut rx: mpsc::Receiver<Event>) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = rx.next().await {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn bc_2_6_turn_limit_emits_notice_and_stops() {
    let provider = Arc::new(AlwaysToolProvider::new());
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 2,
            sandbox_network: true,
            fs_read_deny: vec![],
            fs_protected: vec![],
        },
        provider.clone(),
        Arc::new(LocalApprover),
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("loop forever", tx, CancellationToken::new())
        .await
        .expect("hitting the turn limit is not an error");

    assert_eq!(stop, StopReason::Stop, "PLAN 5: turn limit returns Stop");

    let events = collect_events(rx).await;

    // Exactly max_turns requests, no more.
    assert_eq!(provider.requests.lock().unwrap().len(), 2);

    // Both turns really executed their tool.
    let finished: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::TurnFinished { .. }))
        .collect();
    let tool_finished = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: true, .. }))
        .count();
    assert_eq!(tool_finished, 2, "each turn should have run its tool");

    // The user is told why it stopped, exactly once.
    let notices: Vec<&String> = events
        .iter()
        .filter_map(|e| match e {
            Event::Notice(text) => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(notices.len(), 1, "expected one notice: {events:?}");
    assert_eq!(notices[0], "turn limit reached");

    // ... and the turn still ends with a single TurnFinished{Stop}.
    assert_eq!(finished.len(), 1);
    assert!(matches!(
        finished[0],
        Event::TurnFinished {
            stop: StopReason::Stop,
            ..
        }
    ));
}
