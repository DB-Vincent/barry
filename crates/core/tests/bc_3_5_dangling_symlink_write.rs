/// Regression test: a dangling symlink inside cwd must not let `write`
/// escape it.
///
/// `Path::exists` follows links, so the symlink used to look like a missing
/// component: the canonical path stayed inside cwd, the policy allowed the
/// write with no prompt, and `std::fs::write` followed the link to a file
/// outside cwd.
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
                arguments: json!({ "path": path, "content": "pwned" }),
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
async fn bc_3_5_dangling_symlink_write_does_not_escape_cwd() {
    let ws = Workspace::new();
    let escape_target = ws.outside().join("escaped.txt");
    let link = ws.cwd().join("link");
    std::os::unix::fs::symlink(&escape_target, &link).unwrap();

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

    // `none()` panics if the approver is asked: this path must be decided
    // without a prompt.
    let approver = Arc::new(ScriptedApprover::none());
    let provider = Arc::new(RecordingProvider {
        replies: Mutex::new(
            vec![
                done_write(link.to_str().unwrap()),
                done_text("I could not write the file"),
            ]
            .into(),
        ),
        requests: Mutex::new(Vec::new()),
    });

    let mut agent = Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 10,
            context_window: 32_768,
            sandbox_network: true,
            redact_tool_output: false,
            fs_read_deny: vec![],
            fs_protected: vec![],
            rules: vec![],
            hooks: vec![],
        },
        provider.clone(),
        approver,
        Some(policy),
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write", tx, CancellationToken::new())
        .await
        .expect("denial is not an error");

    assert!(
        !escape_target.exists(),
        "a dangling symlink inside cwd must not create a file outside it"
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .map(|m| !m.file_type().is_file())
            .unwrap_or(false),
        "the link itself must be untouched"
    );

    let requests = provider.requests.lock().unwrap();
    let tool_message = requests[1]
        .messages
        .iter()
        .find(|m| matches!(m, Message::Tool { .. }))
        .expect("one tool result");
    match tool_message {
        Message::Tool { content, ok, .. } => {
            assert!(!ok, "the write must fail: {content}");
            assert!(
                content.contains("dangling symlink"),
                "the model must see why: {content}"
            );
        }
        other => panic!("expected a Tool message, got {other:?}"),
    }
}
