/// BC-3.3 If the user approves, the file is written. A second write to the
/// same directory does not ask. A write to a different outside directory
/// asks again.
///
/// All within one session (one Agent with one Policy carrying grants).
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
async fn bc_3_3_grant_persists_in_session_same_dir_different_dir_asks() {
    let ws = Workspace::new();
    let same_dir = ws.outside().join("same");
    std::fs::create_dir_all(&same_dir).unwrap();
    let file_a = same_dir.join("a.txt");
    let different_dir = ws.outside().join("different");
    std::fs::create_dir_all(&different_dir).unwrap();
    let file_b = different_dir.join("b.txt");

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

    // Turn 1: Deny (no grant yet). Turn 2: AlwaysThisSession (grant added to
    // Policy). Turn 3: Deny (different dir not covered by grant).
    let approver = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::Deny,
        barry_protocol::ApprovalChoice::AlwaysThisSession,
        barry_protocol::ApprovalChoice::Deny,
    ]));
    let approver_clone = approver.clone();

    let provider = Arc::new(RecordingProvider::new(vec![
        done_write(file_a.to_str().unwrap()),
        done_text("denied"),
        done_write(file_a.to_str().unwrap()),
        done_text("written"),
        done_write(file_b.to_str().unwrap()),
        done_text("denied again"),
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

    // Turn 1: write to file_a → Ask → Deny → not written.
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write to file a", tx, CancellationToken::new())
        .await
        .expect("denial is not an error");
    assert_eq!(stop, StopReason::Stop);
    assert!(!file_a.exists(), "file_a must not be written when denied");

    // Turn 2: write to file_a again → Ask → AlwaysThisSession → grant added,
    // file written.
    let (tx2, _rx2) = mpsc::channel(32);
    let stop2 = agent
        .run_turn("write to file a again", tx2, CancellationToken::new())
        .await
        .expect("second turn completes");
    assert_eq!(stop2, StopReason::Stop);
    assert!(file_a.exists(), "file_a must be written after grant");

    // Turn 3: write to file_b (different outside dir) → Ask → Deny → not written.
    let (tx3, _rx3) = mpsc::channel(32);
    let stop3 = agent
        .run_turn("write to file b", tx3, CancellationToken::new())
        .await
        .expect("third turn completes");
    assert_eq!(stop3, StopReason::Stop);
    assert!(!file_b.exists(), "file_b must not be written when denied");

    // Approver consulted 3 times: Deny, AlwaysThisSession, Deny.
    assert_eq!(approver.asked().len(), 3, "approver consulted 3 times");
    for req in &approver.asked() {
        assert_eq!(req.tool, "write");
    }

    // Turn 1: Deny result.
    let requests = provider.requests.lock().unwrap();
    assert!(
        requests.len() >= 2,
        "expected a follow-up request in turn 1"
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
