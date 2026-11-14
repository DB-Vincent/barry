/// BC-2.1 Given the model calls `read` on `README.md`,
/// when the agent runs the turn, then the model receives the file
/// contents with line numbers and the user sees the final answer.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Local scripted provider — avoids a dependency cycle with barry-testkit.
struct LocalProvider {
    replies: Mutex<VecDeque<LlmEvent>>,
    calls: Mutex<Vec<LlmRequest>>,
}

impl LocalProvider {
    fn new(replies: Vec<LlmEvent>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn seen_calls(&self) -> Vec<LlmRequest> {
        self.calls.lock().unwrap().clone()
    }
}

impl barry_llm::Provider for LocalProvider {
    fn stream(
        &self,
        req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
        self.calls.lock().unwrap().push(req);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("LocalProvider: ran out of replies");
        stream::iter(vec![Ok(reply)]).boxed()
    }
}

/// Local approver that always grants approval once.
struct LocalApprover;

impl Approver for LocalApprover {
    fn decide(
        &self,
        _req: &barry_protocol::ApprovalRequest,
    ) -> BoxFuture<'_, barry_protocol::ApprovalChoice> {
        Box::pin(async { barry_protocol::ApprovalChoice::Once })
    }
}

/// Build a Done event carrying final answer text.
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
async fn bc_2_1_read_tool_returns_numbered_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let readme = project.join("README.md");
    std::fs::write(&readme, "# Test Project\n").unwrap();
    let readme_path = readme.to_str().unwrap().to_string();

    // Reply 1: model calls read on the absolute path.
    // Reply 2: model streams the final answer as TextDelta, then Done.
    let provider = Arc::new(LocalProvider::new(vec![
        LlmEvent::Done {
            message: Message::Assistant {
                content: None,
                reasoning: None,
                tool_calls: vec![barry_protocol::ToolCall {
                    id: "call_1".to_string(),
                    name: "read".to_string(),
                    arguments: json!({ "path": readme_path }),
                }],
            },
            stop: StopReason::ToolCalls,
            usage: None,
        },
        LlmEvent::TextDelta("The readme says hello.".to_string()),
        done_text("The readme says hello."),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider.clone(),
        approver,
        None,
    )
    .expect("agent should construct");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("read the readme", tx, CancellationToken::new())
        .await
        .expect("run_turn should succeed");
    assert_eq!(stop, StopReason::Stop);

    let events = collect_events(rx).await;

    // One ToolStarted for the read call.
    let started: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::ToolStarted { .. }))
        .collect();
    assert_eq!(started.len(), 1, "expected one ToolStarted");

    // One successful ToolFinished containing numbered file contents.
    let finished: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: true, .. }))
        .collect();
    assert_eq!(finished.len(), 1, "expected one successful ToolFinished");

    // The display text should contain the numbered file contents.
    let numbered_found = events.iter().any(|e| {
        matches!(e, Event::ToolFinished { display, .. } if display.contains("1: # Test Project"))
    });
    assert!(
        numbered_found,
        "expected numbered file contents in tool result, got: {:?}",
        events
    );

    // One TextDelta from the model's final answer.
    let text_deltas: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::TextDelta(_)))
        .collect();
    assert_eq!(text_deltas.len(), 1);

    // One TurnFinished ending the turn.
    let finished_turns: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::TurnFinished { .. }))
        .collect();
    assert_eq!(finished_turns.len(), 1);

    // The provider saw at least two requests: one that triggered the tool call,
    // and one after the tool result was fed back.
    let calls = provider.seen_calls();
    assert!(
        calls.len() >= 2,
        "expected at least two LLM requests, got {}",
        calls.len()
    );
}
