/// Regression test: "once" is once.
///
/// Both the bash and the write approval paths used to treat `Once` exactly
/// like `AlwaysThisSession`, recording a session-wide prefix or directory
/// grant. One approved command then silently approved every later command
/// with the same first word, and one approved write opened a whole directory.
use barry_core::config::Config;
use barry_core::Agent;
use barry_llm::{LlmEvent, LlmRequest};
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, Message, StopReason};
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

fn done_call(id: &str, name: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![barry_protocol::ToolCall {
                id: id.to_string(),
                name: name.to_string(),
                arguments,
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

fn config() -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        context_window: 32_768,
        sandbox_network: true,
        sandbox_unsandboxed: false,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks: vec![],
    }
}

fn policy(ws: &Workspace) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

#[tokio::test]
async fn bc_3_2_once_write_does_not_grant_the_directory() {
    let ws = Workspace::new();
    let first = ws.outside().join("first.txt");
    let second = ws.outside().join("second.txt");

    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let provider = Arc::new(RecordingProvider::new(vec![
        done_call("call_1", "write", json!({ "path": first, "content": "1" })),
        done_text("wrote one file"),
        done_call("call_2", "write", json!({ "path": second, "content": "2" })),
        done_text("denied"),
    ]));

    let mut agent = Agent::new(config(), provider.clone(), approver.clone(), policy(&ws))
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write the first file", tx, CancellationToken::new())
        .await
        .expect("first turn completes");
    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write the second file", tx, CancellationToken::new())
        .await
        .expect("second turn completes");

    assert!(first.exists(), "the once-approved write must happen");
    assert!(
        !second.exists(),
        "a second write to the same directory must ask again"
    );
    assert_eq!(
        approver.asked().len(),
        2,
        "both writes were outside cwd, so both must prompt"
    );
}

#[tokio::test]
async fn bc_3_9_once_bash_does_not_grant_the_prefix() {
    let ws = Workspace::new();

    let approver = Arc::new(ScriptedApprover::new(vec![
        ApprovalChoice::Once,
        ApprovalChoice::Deny,
    ]));
    let provider = Arc::new(RecordingProvider::new(vec![
        done_call("call_1", "bash", json!({ "command": "true" })),
        done_text("ran"),
        done_call("call_2", "bash", json!({ "command": "true" })),
        done_text("denied"),
    ]));

    let mut agent =
        Agent::new(config(), provider, approver.clone(), policy(&ws)).expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run true", tx, CancellationToken::new())
        .await
        .expect("first turn completes");
    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run true again", tx, CancellationToken::new())
        .await
        .expect("second turn completes");

    assert_eq!(
        approver.asked().len(),
        2,
        "the second command must ask again: once is not always"
    );
}
