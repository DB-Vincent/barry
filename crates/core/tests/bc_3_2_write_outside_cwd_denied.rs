/// BC-3.2 Writing a file outside cwd asks for approval. If the user denies,
/// the file is not created and the model is told "denied by user".
use barry_core::config::Config;
use barry_core::Agent;
use barry_llm::{LlmEvent, LlmRequest};
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{Message, StopReason};
use barry_testkit::{ScriptedApprover, Workspace};
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

fn done_write_outside_cwd(path: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "write".to_string(),
                arguments: json!({ "path": path, "content": "secret" }),
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

#[tokio::test]
async fn bc_3_2_write_outside_cwd_denied_by_user() {
    let ws = Workspace::new();
    let target = ws.outside().join("x.txt");
    assert!(!target.exists());

    let policy = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs");

    let approver = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::Deny,
    ]));
    let approver_clone = approver.clone();

    let provider = Arc::new(RecordingProvider::new(vec![
        done_write_outside_cwd(target.to_str().unwrap()),
        done_text("I could not write the file"),
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
        approver_clone,
        Some(policy),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn(
            "write a secret file outside cwd",
            tx,
            CancellationToken::new(),
        )
        .await
        .expect("denial is not an error");
    assert_eq!(stop, StopReason::Stop);

    // The file must not be created.
    assert!(!target.exists(), "file must not be written when denied");

    // The model must be told the write was denied.
    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");
    let tool_messages: Vec<&Message> = requests[1]
        .messages
        .iter()
        .filter(|m| matches!(m, Message::Tool { .. }))
        .collect();
    assert_eq!(tool_messages.len(), 1, "exactly one result per call");
    match &tool_messages[0] {
        Message::Tool { content, ok, .. } => {
            assert!(!ok, "write denial must be ok:false");
            assert!(
                content.contains("denied by user"),
                "model must be told 'denied by user': {content}"
            );
        }
        other => panic!("expected a Tool message, got {other:?}"),
    }

    // The approver was consulted exactly once.
    assert_eq!(approver.asked().len(), 1, "approver consulted once");
    assert_eq!(approver.asked()[0].tool, "write");
}
