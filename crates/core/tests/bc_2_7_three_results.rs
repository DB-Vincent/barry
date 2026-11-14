/// BC-2.7 Given three tool calls in one reply where one fails internally, the
/// next request carries exactly three tool results, in call order.
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

fn done_three_reads(one: &str, two: &str, three: &str) -> LlmEvent {
    let call = |id: &str, path: &str| barry_protocol::ToolCall {
        id: id.to_string(),
        name: "read".to_string(),
        arguments: json!({ "path": path }),
    };
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![
                call("call_1", one),
                call("call_2", two),
                call("call_3", three),
            ],
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
async fn bc_2_7_three_results_in_call_order_when_one_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("a.txt");
    let third = dir.path().join("c.txt");
    std::fs::write(&first, "alpha").expect("write a");
    std::fs::write(&third, "gamma").expect("write c");
    // The middle call points at a file that does not exist: an internal error.
    let missing = dir.path().join("missing.txt");

    let provider = Arc::new(RecordingProvider::new(vec![
        done_three_reads(
            first.to_str().unwrap(),
            missing.to_str().unwrap(),
            third.to_str().unwrap(),
        ),
        LlmEvent::TextDelta("a is alpha, c is gamma, the middle failed".to_string()),
        done_text("a is alpha, c is gamma, the middle failed"),
    ]));
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
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
        .run_turn("read the three files", tx, CancellationToken::new())
        .await
        .expect("one failing tool must not abort the turn");
    assert_eq!(stop, StopReason::Stop, "the turn continues to the model");

    let events = collect_events(rx).await;
    let ok_count = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: true, .. }))
        .count();
    let failed_count = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: false, .. }))
        .count();
    assert_eq!((ok_count, failed_count), (2, 1), "events: {events:?}");

    // The request after the tool calls carries exactly three results, in order.
    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");
    let results: Vec<(&str, bool, &str)> = requests[1]
        .messages
        .iter()
        .filter_map(|m| match m {
            Message::Tool {
                tool_call_id,
                content,
                ok,
            } => Some((tool_call_id.as_str(), *ok, content.as_str())),
            _ => None,
        })
        .collect();

    assert_eq!(results.len(), 3, "exactly one result per call: {results:?}");
    assert_eq!(
        results.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec!["call_1", "call_2", "call_3"],
        "results must follow call order"
    );
    assert!(results[0].1, "first read succeeds");
    assert!(!results[1].1, "the missing file fails");
    assert!(results[2].1, "third read still runs after the failure");

    assert!(
        results[1].2.contains("internal tool error"),
        "PLAN 5: a tool error becomes an 'internal tool error' result: {}",
        results[1].2
    );
    assert!(results[0].2.contains("alpha"));
    assert!(results[2].2.contains("gamma"));
}
