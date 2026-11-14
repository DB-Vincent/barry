/// PLAN 5 (tool result wrapping) and 5.1 (bash returns exit_code, stdout and
/// stderr). Neither has its own BC number, so this pins both shapes:
///
///   <tool_output tool="read" ok="true">
///   1: alpha
///   </tool_output>
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

fn done_tool_call(name: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: name.to_string(),
                arguments,
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

/// Runs one tool call and returns the content the model was handed.
async fn tool_result_content(
    dev_unsafe_bash: bool,
    name: &str,
    arguments: serde_json::Value,
) -> String {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool_call(name, arguments),
        LlmEvent::TextDelta("done".to_string()),
        done_text("done"),
    ]));
    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash,
        },
        provider.clone(),
        Arc::new(LocalApprover),
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    agent
        .run_turn("go", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    let _ = collect_events(rx).await;

    let requests = provider.requests.lock().unwrap();
    requests
        .iter()
        .flat_map(|req| req.messages.iter())
        .find_map(|m| match m {
            Message::Tool { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("a request carries the tool result")
}

#[tokio::test]
async fn read_result_is_wrapped_in_tool_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("a.txt");
    std::fs::write(&path, "alpha").expect("write");

    let content =
        tool_result_content(false, "read", json!({ "path": path.to_str().unwrap() })).await;

    assert_eq!(
        content,
        "<tool_output tool=\"read\" ok=\"true\">\n1: alpha\n</tool_output>"
    );
}

#[tokio::test]
async fn bash_result_carries_exit_code_stdout_and_stderr() {
    let content = tool_result_content(
        true,
        "bash",
        json!({ "command": "echo out; echo err >&2; exit 3" }),
    )
    .await;

    assert!(
        content.starts_with("<tool_output tool=\"bash\" ok=\"false\">"),
        "a failing command is ok=\"false\": {content}"
    );
    assert!(content.ends_with("</tool_output>"), "{content}");
    assert!(content.contains("exit_code: 3"), "{content}");
    assert!(content.contains("stdout: out"), "{content}");
    assert!(content.contains("stderr: err"), "{content}");
}

#[tokio::test]
async fn successful_bash_result_also_carries_all_three() {
    let content = tool_result_content(true, "bash", json!({ "command": "echo hi" })).await;

    assert!(
        content.starts_with("<tool_output tool=\"bash\" ok=\"true\">"),
        "{content}"
    );
    assert!(content.contains("exit_code: 0"), "{content}");
    assert!(content.contains("stdout: hi"), "{content}");
    assert!(content.contains("stderr:"), "{content}");
}
