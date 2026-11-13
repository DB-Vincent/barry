/// BC-2.11 The tool list sent to the model contains exactly
/// `read, write, edit, bash, agent`, and the system prompt matches the
/// approved snapshot (insta).
///
/// The prompt is checked through the wire-shaped `LlmRequest` rather than by
/// calling the builder directly, so the snapshot covers what the model really
/// receives. The cwd and date are session facts, so they are normalised before
/// snapshotting; the rest is the approved PLAN 5.2 template.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Event, Message, StopReason};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
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
                arguments: json!({ "task": "look around" }),
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
async fn bc_2_11_tool_list_is_exact_and_prompt_matches_snapshot() {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_agent_call(),
        LlmEvent::TextDelta("ok".to_string()),
        done_text("ok"),
    ]));
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider.clone(),
        Arc::new(LocalApprover),
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    agent
        .run_turn("look around", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    let _ = collect_events(rx).await;

    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");

    // Exactly the five tools, in the order PLAN 5.1 lists them.
    let names: Vec<&str> = requests[0]
        .tools
        .iter()
        .map(|spec| spec.name.as_str())
        .collect();
    assert_eq!(names, ["read", "write", "edit", "bash", "agent"]);

    let system_of = |index: usize| -> String {
        match &requests[index].messages[0] {
            Message::System { content } => content.clone(),
            other => panic!("expected a system message first, got {other:?}"),
        }
    };
    let first = system_of(0);
    let second = system_of(1);

    // PLAN 5.2: byte-identical across turns so providers can cache the prefix.
    assert_eq!(
        first, second,
        "the system prompt must not change between turns"
    );

    let cwd = std::env::current_dir().expect("cwd").display().to_string();
    let date = barry_core::prompt::today();
    let normalized = first
        .replace(&cwd, "[CWD]")
        .replace(&date, "[DATE]")
        .replace(std::env::consts::OS, "[OS]");

    insta::assert_snapshot!(normalized);
}
