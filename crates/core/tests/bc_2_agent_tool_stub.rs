/// PLAN 5.1 lists `agent` as one of the five tools, and BC-2.11 requires the
/// advertised list to contain exactly read, write, edit, bash, agent. The
/// sub-agent itself is PLAN 6.6 (M8), so until then the tool must exist and
/// answer honestly instead of looking like a typo ("unknown tool").
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

fn done_agent_call() -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "agent".to_string(),
                arguments: json!({ "task": "summarise the repo", "allow_writes": false }),
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
async fn agent_tool_is_advertised_and_honestly_unavailable() {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_agent_call(),
        LlmEvent::TextDelta("no sub-agents yet".to_string()),
        done_text("no sub-agents yet"),
    ]));
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider.clone(),
        Arc::new(LocalApprover),
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("delegate this", tx, CancellationToken::new())
        .await
        .expect("an unavailable tool is not an error");
    assert_eq!(stop, StopReason::Stop);

    let events = collect_events(rx).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolFinished { ok: false, .. })),
        "events: {events:?}"
    );

    let requests = provider.requests.lock().unwrap();
    // Advertised: the first request's tool list names it.
    assert!(
        requests[0].tools.iter().any(|t| t.name == "agent"),
        "the agent tool must be in the advertised list"
    );

    let content = requests[1]
        .messages
        .iter()
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a request carries the tool result");

    assert!(
        content.contains("sub-agent"),
        "the model should be told what is missing: {content}"
    );
    assert!(
        !content.contains("unknown tool"),
        "an advertised tool must not look like a typo: {content}"
    );
}
