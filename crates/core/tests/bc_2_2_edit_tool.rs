/// BC-2.2 `edit` with a unique `old_string` changes the file.
/// With a non-unique one the file is unchanged and the model is told
/// how many matches there were.
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

fn done_edit(path: &str, old: &str, new: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "edit".to_string(),
                arguments: json!({ "path": path, "old_string": old, "new_string": new }),
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
async fn bc_2_2_edit_unique_match_changes_file() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let file = project.join("example.txt");
    std::fs::write(&file, "hello world\nhello there\n").unwrap();
    let path = file.to_str().unwrap().to_string();

    let provider = Arc::new(LocalProvider::new(vec![
        done_edit(&path, "hello world", "hello universe"),
        done_text("done."),
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
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("edit the file", tx, CancellationToken::new())
        .await
        .expect("ok");
    assert_eq!(stop, StopReason::Stop);

    let events = collect_events(rx).await;
    let finished: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: true, .. }))
        .collect();
    assert_eq!(finished.len(), 1);

    let contents = std::fs::read_to_string(&file).unwrap();
    assert_eq!(contents, "hello universe\nhello there\n");
}

#[tokio::test]
async fn bc_2_2_edit_non_unique_no_change() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let file = project.join("example.txt");
    std::fs::write(&file, "repeat repeat repeat\n").unwrap();
    let path = file.to_str().unwrap().to_string();

    let provider = Arc::new(LocalProvider::new(vec![
        done_edit(&path, "repeat", "once"),
        done_text("tried."),
    ]));
    let approver = Arc::new(LocalApprover);

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider,
        approver,
        None,
    )
    .expect("agent constructs");

    let (tx, rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("edit the file", tx, CancellationToken::new())
        .await
        .expect("ok");
    assert_eq!(stop, StopReason::Stop);

    let contents = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        contents, "repeat repeat repeat\n",
        "file must be unchanged for non-unique match"
    );

    // Check a ToolFinished with ok=false exists (the model was told about matches)
    let events = collect_events(rx).await;
    let failed: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::ToolFinished { ok: false, .. }))
        .collect();
    assert_eq!(
        failed.len(),
        1,
        "expected one failed ToolFinished reporting match count"
    );
}
