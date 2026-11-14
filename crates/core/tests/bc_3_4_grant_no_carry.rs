/// BC-3.4 A grant does not carry over to a new session.
///
/// A fresh Agent (new Policy) re-asks for the same outside directory,
/// because the previous session's grants are gone.
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

fn done_write(path: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "write".to_string(),
                arguments: json!({ "path": path, "content": "hi" }),
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
async fn bc_3_4_grant_does_not_carry_to_new_session() {
    let ws = Workspace::new();
    let target = ws.outside().join("session_test.txt");

    // Session 1: approve the write.
    let policy1 = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
    })
    .expect("policy constructs");

    let approver1 = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::AlwaysThisSession,
    ]));
    let provider1 = Arc::new(RecordingProvider::new(vec![
        done_write(target.to_str().unwrap()),
        done_text("written in session 1"),
    ]));

    let mut agent1 = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider1.clone(),
        approver1,
        Some(policy1),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let stop1 = agent1
        .run_turn("write the file", tx, CancellationToken::new())
        .await
        .expect("session 1 completes");
    assert_eq!(stop1, StopReason::Stop);
    assert!(target.exists(), "file must be written in session 1");

    // Session 2: fresh Agent, fresh Policy — no grant carries over.
    // The same write asks again; approver says Deny.
    let policy2 = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
    })
    .expect("policy constructs");

    let approver2 = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::Deny,
    ]));
    let provider2 = Arc::new(RecordingProvider::new(vec![
        done_write(target.to_str().unwrap()),
        done_text("not written in session 2"),
    ]));

    let mut agent2 = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider2.clone(),
        approver2,
        Some(policy2),
    )
    .expect("agent constructs");

    let (tx2, _rx2) = mpsc::channel(32);
    let stop2 = agent2
        .run_turn("write the file again", tx2, CancellationToken::new())
        .await
        .expect("session 2 completes");
    assert_eq!(stop2, StopReason::Stop);

    // File already exists from session 1; write would overwrite it, but the
    // approval is denied so the write is not attempted.
    // (The file content is unchanged since session 1.)
    let content = std::fs::read_to_string(&target).expect("file exists from session 1");
    assert_eq!(content, "hi", "file content unchanged from session 1");

    // Session 2's model was told the write was denied.
    let requests = provider2.requests.lock().unwrap();
    assert!(
        requests.len() >= 2,
        "expected a follow-up request in session 2"
    );
    let tool_msgs: Vec<&Message> = requests[1]
        .messages
        .iter()
        .filter(|m| matches!(m, Message::Tool { .. }))
        .collect();
    assert_eq!(tool_msgs.len(), 1);
    match &tool_msgs[0] {
        Message::Tool { content, ok, .. } => {
            assert!(!ok);
            assert!(content.contains("denied by user"));
        }
        other => panic!("expected Tool message, got {other:?}"),
    }
}
