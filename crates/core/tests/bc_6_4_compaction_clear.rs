//! BC-6.4 / 6.5 Compaction: when the context estimate passes the threshold,
//! old tool outputs are cleared first; if that is not enough, a summary is
//! requested and the old messages are replaced.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Message, StopReason, ToolCall};
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

impl Provider for RecordingProvider {
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

struct AlwaysAllow;
impl Approver for AlwaysAllow {
    fn decide(&self, _req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        Box::pin(async { ApprovalChoice::Once })
    }
}

fn done_tool(name: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: name.to_string(),
                arguments,
            }],
        },
        stop: StopReason::ToolCalls,
        usage: None,
    }
}

fn done_text(content: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: Some(content.to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
        stop: StopReason::Stop,
        usage: None,
    }
}

fn config_with_window(window: u64) -> barry_core::config::Config {
    barry_core::config::Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: window,
        sandbox_network: true,
        fs_read_deny: vec![],
        fs_protected: vec![],
    }
}

#[tokio::test]
async fn bc_6_5_summarises_when_clearing_is_not_enough() {
    // Small context window: threshold = 20000 - 16384 = 3616 estimated tokens.
    // The single bash result (~6,000 tokens) is under the 20,000-token keep
    // window, so clearing does nothing and a summarisation request is sent.
    let provider = Arc::new(RecordingProvider::new(vec![
        // Turn 1: ask for a bash command.
        done_tool(
            "bash",
            json!({"command": "head -c 100000 /dev/zero | tr '\\0' 'x'"}),
        ),
        // The summarisation request (step 2) is answered with a summary.
        done_text("the summary"),
        // Turn 2: after summarisation, the model answers.
        done_text("done"),
    ]));

    let mut agent = Agent::new(
        config_with_window(20_000),
        provider.clone(),
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run a command", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let requests = provider.requests.lock().unwrap().clone();
    // Turn 1, the summarisation request, then turn 2.
    assert_eq!(requests.len(), 3, "expected 3 requests: {requests:?}");

    // The second request is the summarisation request (no tools).
    let summarise = &requests[1];
    assert!(
        summarise.tools.is_empty(),
        "summarise has no tools: {summarise:?}"
    );
    let has_summary_prompt = summarise
        .messages
        .iter()
        .any(|m| matches!(m, Message::User { content } if content.contains("Summarise")));
    assert!(
        has_summary_prompt,
        "summarisation request contains the summary prompt: {summarise:?}"
    );

    // Turn 2 receives the summary, not the raw tool output.
    let turn2 = &requests[2];
    let rendered = serde_json::to_string(turn2).unwrap();
    assert!(
        rendered.contains("[Summary of earlier conversation]"),
        "turn 2 carries the summary: {rendered}"
    );
    assert!(
        rendered.contains("the summary"),
        "turn 2 carries the summary text: {rendered}"
    );
    assert!(
        !rendered.contains("head -c"),
        "turn 2 does not carry the raw tool output: {rendered}"
    );
}
