/// BC-2.5 Output larger than 30,000 bytes reaches the model as head + tail
/// with a truncation marker stating the original size.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Replies from a script, and remembers every request it was handed.
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
                arguments: json!({ "command": command, "timeout": 30 }),
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
async fn bc_2_5_large_output_is_truncated() {
    // Exactly 60,000 bytes of 'a', no newline.
    let command = "head -c 60000 /dev/zero | tr '\\0' a";
    let provider = Arc::new(RecordingProvider::new(vec![
        done_bash(command),
        LlmEvent::TextDelta("done".to_string()),
        done_text("done"),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 10,
        },
        provider.clone(),
        approver,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("print a lot", tx, CancellationToken::new())
        .await
        .expect("ok");
    assert_eq!(stop, StopReason::Stop);

    let _events = collect_events(rx).await;

    // The second request is the one that carries the tool result back.
    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected at least two provider calls");

    let tool_content = requests
        .iter()
        .flat_map(|req| req.messages.iter())
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a request carries the Tool message");

    assert_eq!(
        tool_content
            .matches("[... truncated 36000 of 60000 bytes ...]")
            .count(),
        1,
        "expected exactly one truncation marker: {tool_content:.200}"
    );
    assert!(tool_content.starts_with(&"a".repeat(12_000)));
    assert!(tool_content.ends_with(&"a".repeat(12_000)));
}
