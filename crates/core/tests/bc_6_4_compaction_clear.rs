//! BC-6.4 Compaction reduces memory without losing the conversation: old tool
//! outputs are cleared first, then only the turns before the newest ones are
//! summarised. The request being answered and its pending tool calls stay
//! verbatim, and an empty summary never replaces the context (#21).
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
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    }
}

/// A 20,000-byte bash output: big enough that four turns exceed the threshold
/// of a 30,000-token window (13,616 estimated tokens, ~54 KB) while two turns
/// stay under it.
fn bash_filling(byte: &str) -> LlmEvent {
    done_tool(
        "bash",
        json!({ "command": format!("head -c 20000 /dev/zero | tr '\\0' '{byte}'") }),
    )
}

/// Replies for four turns that each leave a large tool output behind.
///
/// The summarisation request comes before turn three's answer: turn three's
/// second request is the first one over the threshold.
fn four_turn_replies() -> Vec<LlmEvent> {
    vec![
        bash_filling("a"),
        done_text("first done"),
        bash_filling("b"),
        done_text("second done"),
        bash_filling("c"),
        done_text("the summary"),
        done_text("third done"),
        done_text("fourth done"),
    ]
}

async fn run(agent: &mut Agent, prompt: &str) -> StopReason {
    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn(prompt, tx, CancellationToken::new())
        .await
        .expect("turn completes")
}

#[tokio::test]
async fn bc_6_4_summarises_older_turns_and_keeps_the_newest() {
    let provider = Arc::new(RecordingProvider::new(four_turn_replies()));
    let mut agent = Agent::new(
        config_with_window(30_000),
        provider.clone(),
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent");

    assert_eq!(run(&mut agent, "first request").await, StopReason::Stop);
    assert_eq!(run(&mut agent, "second request").await, StopReason::Stop);
    assert_eq!(run(&mut agent, "third request").await, StopReason::Stop);
    assert_eq!(run(&mut agent, "fourth request").await, StopReason::Stop);

    let requests = provider.requests.lock().unwrap().clone();
    // Turns one and two cost a request before and after their tool call; turn
    // three's second request is the first one over the threshold, so it is
    // preceded by the summarisation request.
    assert_eq!(requests.len(), 8, "expected 8 requests");

    // The summarisation request carries only the turn it replaces.
    let summarise = serde_json::to_string(&requests[5]).unwrap();
    assert!(requests[5].tools.is_empty(), "summarise has no tools");
    assert!(summarise.contains("Summarise"), "{summarise:.200}");
    assert!(
        summarise.contains("first request"),
        "it summarises the oldest turn: {summarise:.200}"
    );
    assert!(
        !summarise.contains("second request") && !summarise.contains("third request"),
        "it leaves the recent turns alone: {summarise:.200}"
    );

    // The request sent straight after: summary in place of turn one, the
    // previous turn and the in-flight turn three verbatim.
    let kept = serde_json::to_string(&requests[6]).unwrap();
    assert!(
        kept.contains("[Summary of earlier conversation]") && kept.contains("the summary"),
        "the summary replaces the older turn: {kept:.200}"
    );
    assert!(
        kept.contains("third request") && kept.contains("'c'"),
        "the request being answered and its pending tool call are kept: {kept:.200}"
    );
    assert!(
        kept.contains("second done") && kept.contains("'b'"),
        "the previous turn is kept verbatim: {kept:.200}"
    );
    assert!(
        !kept.contains("first request") && !kept.contains("'a'"),
        "only the summarised turn is gone: {kept:.200}"
    );

    // The history stays compacted for the next turn.
    let fourth = serde_json::to_string(&requests[7]).unwrap();
    assert!(
        fourth.contains("[Summary of earlier conversation]") && fourth.contains("fourth request"),
        "the next turn carries the summary and its own request: {fourth:.200}"
    );
}

#[tokio::test]
async fn bc_6_4_an_empty_summary_leaves_the_context_alone() {
    let provider = Arc::new(RecordingProvider::new(vec![
        done_text("previous answer"),
        // The summarisation request is answered with nothing at all.
        done_text(""),
        done_text("after"),
    ]));
    let mut agent = Agent::new(
        config_with_window(30_000),
        provider.clone(),
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent");

    assert_eq!(run(&mut agent, "a previous turn").await, StopReason::Stop);
    let compacted = agent.compact().await.expect("compact runs");
    assert!(
        !compacted,
        "a summary with no text must not replace the context"
    );

    assert_eq!(run(&mut agent, "after").await, StopReason::Stop);

    let requests = provider.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    let rendered = serde_json::to_string(&requests[2]).unwrap();
    assert!(
        rendered.contains("a previous turn") && rendered.contains("previous answer"),
        "the history survived the empty summary: {rendered:.200}"
    );
    assert!(!rendered.contains("[Summary of earlier conversation]"));
}
