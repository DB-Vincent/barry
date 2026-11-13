/// BC-3.9 After "always this session" on a bash command, the same command
/// prefix runs without asking in the same session. A new session asks again.
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

fn done_bash(command: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: "call_1".to_string(),
                name: "bash".to_string(),
                arguments: json!({ "command": command }),
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
async fn bc_3_9_bash_always_this_session_persists_in_session() {
    let ws = Workspace::new();

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

    // Turn 1: AlwaysThisSession → grant added for "true" prefix.
    // Turn 2: Same prefix → Allow (no approver call).
    let approver = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::AlwaysThisSession,
    ]));
    let provider = Arc::new(RecordingProvider::new(vec![
        done_bash("true"),
        done_text("done"),
        done_bash("true"),
        done_text("done again"),
    ]));

    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: true,
        },
        provider.clone(),
        approver.clone(),
        Some(policy),
    )
    .expect("agent constructs");

    // Turn 1: bash true → Ask → AlwaysThisSession → runs → exit_code 0.
    let (tx, _rx) = mpsc::channel(32);
    let stop1 = agent
        .run_turn("run true", tx, CancellationToken::new())
        .await
        .expect("turn 1 completes");
    assert_eq!(stop1, StopReason::Stop);

    // Turn 2: bash true → prefix grant matches → Allow, no approver call.
    let (tx2, _rx2) = mpsc::channel(32);
    let stop2 = agent
        .run_turn("run true again", tx2, CancellationToken::new())
        .await
        .expect("turn 2 completes");
    assert_eq!(stop2, StopReason::Stop);

    // Approver consulted exactly once (turn 1 only).
    assert_eq!(approver.asked().len(), 1, "approver consulted once");
    assert_eq!(approver.asked()[0].tool, "bash");

    // Turn 1 result: ok:true (command ran and exited 0).
    {
        let requests = provider.requests.lock().unwrap();
        assert!(requests.len() >= 2, "expected follow-up request in turn 1");
        let tool_msgs: Vec<&Message> = requests[1]
            .messages
            .iter()
            .filter(|m| matches!(m, Message::Tool { .. }))
            .collect();
        assert_eq!(tool_msgs.len(), 1);
        match &tool_msgs[0] {
            Message::Tool { content, ok, .. } => {
                assert!(*ok, "bash should succeed: {content}");
                assert!(content.contains("exit_code: 0"), "exit_code: 0: {content}");
            }
            other => panic!("expected Tool message, got {other:?}"),
        }
    } // requests guard dropped here, before the next .await

    // New session: fresh Policy, no grants → Ask again for true.
    let policy2 = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs");

    let approver2 = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::Deny,
    ]));
    let provider2 = Arc::new(RecordingProvider::new(vec![
        done_bash("true"),
        done_text("denied"),
    ]));

    let mut agent2 = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            dev_unsafe_bash: true,
        },
        provider2.clone(),
        approver2,
        Some(policy2),
    )
    .expect("agent constructs");

    let (tx3, _rx3) = mpsc::channel(32);
    let stop3 = agent2
        .run_turn("run true again", tx3, CancellationToken::new())
        .await
        .expect("turn 3 completes");
    assert_eq!(stop3, StopReason::Stop);

    // Turn 3: bash true → Ask → Deny → not run.
    let requests2 = provider2.requests.lock().unwrap();
    assert!(requests2.len() >= 2, "expected follow-up request in turn 3");
    let tool_msgs2: Vec<&Message> = requests2[1]
        .messages
        .iter()
        .filter(|m| matches!(m, Message::Tool { .. }))
        .collect();
    assert_eq!(tool_msgs2.len(), 1);
    match &tool_msgs2[0] {
        Message::Tool { content, ok, .. } => {
            assert!(!ok, "bash should be denied: {content}");
        }
        other => panic!("expected Tool message, got {other:?}"),
    }
}
