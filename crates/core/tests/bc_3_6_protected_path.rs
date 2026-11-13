/// BC-3.6 Writing `.git/hooks/pre-commit` inside cwd asks for approval.
///
/// Protected path components (e.g. `.git`) always trigger Ask, even for
/// paths inside cwd.
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
                arguments: json!({ "path": path, "content": "hook content" }),
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
async fn bc_3_6_protected_path_inside_cwd_asks() {
    let ws = Workspace::new();
    // .git/hooks/pre-commit inside cwd
    let hooks_dir = ws.cwd().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let target = hooks_dir.join("pre-commit");

    let policy = Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![".git".to_string(), ".barry".to_string()],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs");

    let approver = Arc::new(ScriptedApprover::new(vec![
        barry_protocol::ApprovalChoice::Deny,
    ]));
    let provider = Arc::new(RecordingProvider::new(vec![
        done_write(target.to_str().unwrap()),
        done_text("not written"),
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
        approver,
        Some(policy),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("write to protected path", tx, CancellationToken::new())
        .await
        .expect("denial is not an error");
    assert_eq!(stop, StopReason::Stop);
    assert!(
        !target.exists(),
        "protected path must not be written when denied"
    );

    // Model was told the write was denied.
    let requests = provider.requests.lock().unwrap();
    assert!(requests.len() >= 2, "expected a follow-up request");
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
