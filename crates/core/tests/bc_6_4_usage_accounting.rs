//! PLAN 6.4 / #23 The compaction estimate uses the token usage the provider
//! reports, so a context that is over the window is compacted even when the
//! message bytes alone look small.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{
    ApprovalChoice, ApprovalRequest, Event, Message, StopReason, ToolCall, Usage,
};
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

#[tokio::test]
async fn bc_6_4_reported_usage_drives_the_context_estimate() {
    // 30,100 reported tokens against a 20,000-token window: over the threshold
    // (20,000 - 16,384) even though the history itself is a few hundred bytes.
    let provider = Arc::new(RecordingProvider::new(vec![LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: "bash".to_string(),
                arguments: json!({ "command": "true" }),
            }],
        },
        stop: StopReason::ToolCalls,
        usage: Some(Usage {
            input_tokens: 30_000,
            output_tokens: 100,
        }),
    }]));

    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "local".to_string(),
            max_turns: 50,
            context_window: 20_000,
            sandbox_network: false,
            redact_tool_output: false,
            fs_read_deny: vec![],
            fs_protected: vec![],
            rules: vec![],
            hooks: vec![],
        },
        provider.clone(),
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent");

    let (tx, mut rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("do it", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    assert_eq!(
        stop,
        StopReason::ContextFull,
        "reported usage over the window must stop the turn"
    );
    assert_eq!(
        provider.requests.lock().unwrap().len(),
        1,
        "the follow-up request is never sent"
    );

    let mut reported = None;
    while let Some(event) = rx.next().await {
        if let Event::TurnFinished { usage, .. } = event {
            reported = usage;
        }
    }
    let reported = reported.expect("TurnFinished carries the reported usage");
    assert_eq!(
        (reported.input_tokens, reported.output_tokens),
        (30_000, 100),
        "the turn reports what the provider said"
    );
}
