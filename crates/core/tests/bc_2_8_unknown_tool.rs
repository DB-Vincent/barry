/// BC-2.8 An unknown tool name sends the model an ok:false result "unknown tool".
///
/// The behaviour already exists (the catch-all arm in `tools::execute_tool`);
/// this pins it, so a later refactor that turns an unknown name into an error
/// or a silent drop fails here.
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

fn done_unknown_tool() -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "teleporter".to_string(),
                arguments: json!({ "target": "mars" }),
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
async fn bc_2_8_unknown_tool_is_ok_false_result() {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_unknown_tool(),
        LlmEvent::TextDelta("I cannot do that".to_string()),
        done_text("I cannot do that"),
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
        .run_turn("go to mars", tx, CancellationToken::new())
        .await
        .expect("an unknown tool is not an error");

    assert_eq!(stop, StopReason::Stop, "the turn continues to the model");
    let events = collect_events(rx).await;

    // The user sees a failed tool call, not a crash.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolFinished { ok: false, .. })),
        "expected a failed ToolFinished: {events:?}"
    );

    // The model receives exactly one Tool message for the call, ok:false, and
    // it names the tool so the model can correct itself.
    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");

    let tool_messages: Vec<&Message> = requests[1]
        .messages
        .iter()
        .filter(|m| matches!(m, Message::Tool { .. }))
        .collect();
    assert_eq!(
        tool_messages.len(),
        1,
        "exactly one result per call id: {:?}",
        requests[1].messages
    );

    match tool_messages[0] {
        Message::Tool {
            tool_call_id,
            content,
            ok,
        } => {
            assert_eq!(tool_call_id, "call_1");
            assert!(!ok, "an unknown tool must be ok:false");
            assert!(
                content.contains("unknown tool"),
                "expected 'unknown tool' in the result: {content}"
            );
            assert!(
                content.contains("teleporter"),
                "the result should name the tool: {content}"
            );
        }
        other => panic!("expected a Tool message, got {other:?}"),
    }
}
