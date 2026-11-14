/// BC-3.7 Reading `~/.ssh/id_test` is refused without a prompt, and the
/// model never receives `FAKE-PRIVATE-KEY`. Reading a normal file outside
/// cwd is allowed.
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

fn done_read(path: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "read".to_string(),
                arguments: json!({ "path": path }),
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
async fn bc_3_7_read_deny_blocks_secret_and_allows_normal_outside_read() {
    let ws = Workspace::new();
    let ssh_key = ws.home().join(".ssh").join("id_test");
    assert_eq!(
        std::fs::read_to_string(&ssh_key).expect("fixture exists"),
        "FAKE-PRIVATE-KEY"
    );

    // A normal file outside cwd (e.g. outside/readable.txt) is allowed to read.
    let outside_file = ws.outside().join("readable.txt");
    std::fs::write(&outside_file, "public data").expect("write fixture");

    let policy = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec!["~/.ssh".to_string()],
        protected: vec![],
        rules: vec![],
    })
    .expect("policy constructs");
    let policy2 = policy.clone();

    let provider = Arc::new(RecordingProvider::new(vec![
        // Read the secret: model gets Deny, no tool result content.
        done_read(ssh_key.to_str().unwrap()),
        done_text("I cannot read that file"),
        // Read a normal outside file: Allow, content returned.
        done_read(outside_file.to_str().unwrap()),
        done_text("the file says public data"),
    ]));

    // Use ScriptedApprover::none() to assert no approval prompt happens for reads.
    let no_approver = Arc::new(ScriptedApprover::none());
    let no_approver2 = no_approver.clone();

    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider.clone(),
        no_approver,
        Some(policy),
    )
    .expect("agent constructs");

    // Turn 1: read the secret → Deny, no approval prompt, model never sees FAKE-PRIVATE-KEY.
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("read the ssh key", tx, CancellationToken::new())
        .await
        .expect("denial is not an error");
    assert_eq!(stop, StopReason::Stop);

    // No approval was requested (read-deny is a policy Deny, not an Ask).
    {
        let requests = provider.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "two model requests (read + follow-up text)"
        );

        // Check the tool result for the denied read: ok:false, no secret content.
        let tool_msgs: Vec<&Message> = requests[1]
            .messages
            .iter()
            .filter(|m| matches!(m, Message::Tool { .. }))
            .collect();
        assert_eq!(tool_msgs.len(), 1);
        match &tool_msgs[0] {
            Message::Tool { content, ok, .. } => {
                assert!(!ok);
                assert!(
                    !content.contains("FAKE-PRIVATE-KEY"),
                    "secret must not reach model: {content}"
                );
            }
            other => panic!("expected Tool message, got {other:?}"),
        }
    } // requests guard dropped here, before the next .await

    // Turn 2: read a normal outside file → Allow → content returned.
    let provider2 = Arc::new(RecordingProvider::new(vec![
        done_read(outside_file.to_str().unwrap()),
        done_text("the file says public data"),
    ]));
    let mut agent2 = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: false,
        },
        provider2.clone(),
        no_approver2.clone(),
        Some(policy2),
    )
    .expect("agent constructs");

    let (tx2, _rx2) = mpsc::channel(32);
    let stop2 = agent2
        .run_turn("read the outside file", tx2, CancellationToken::new())
        .await
        .expect("allow is not an error");
    assert_eq!(stop2, StopReason::Stop);

    let requests2 = provider2.requests.lock().unwrap();
    assert!(requests2.len() >= 2, "expected a follow-up request");
    let tool_msgs2: Vec<&Message> = requests2[1]
        .messages
        .iter()
        .filter(|m| matches!(m, Message::Tool { .. }))
        .collect();
    assert_eq!(tool_msgs2.len(), 1);
    match &tool_msgs2[0] {
        Message::Tool { content, ok, .. } => {
            assert!(*ok);
            assert!(
                content.contains("public data"),
                "outside read content: {content}"
            );
        }
        other => panic!("expected Tool message, got {other:?}"),
    }
}
