#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::Agent;
/// The read-only `glob`, `grep` and `ls` tools go through the read policy:
/// a read-denied root is refused, read-denied entries inside an allowed root
/// are neither listed nor searched, and no approval prompt appears.
use barry_core::config::Config;
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

fn call(id: &str, name: &str, arguments: serde_json::Value) -> barry_protocol::ToolCall {
    barry_protocol::ToolCall {
        id: id.to_string(),
        name: name.to_string(),
        arguments,
    }
}

#[tokio::test]
async fn search_tools_respect_read_deny() {
    let ws = Workspace::new();
    let cwd = ws.cwd().to_path_buf();
    let vault = cwd.join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(vault.join("secret.txt"), "TOPSECRET needle").unwrap();
    std::fs::write(cwd.join("public.txt"), "public needle").unwrap();
    let cwd_str = cwd.to_str().unwrap();

    let policy = Policy::new(PolicyConfig {
        cwd: cwd.clone(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![vault.display().to_string()],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs");

    let provider = Arc::new(RecordingProvider::new(vec![
        LlmEvent::Done {
            message: Message::Assistant {
                content: None,
                reasoning: None,
                tool_calls: vec![
                    call(
                        "c1",
                        "grep",
                        json!({ "pattern": "needle", "path": cwd_str }),
                    ),
                    call("c2", "glob", json!({ "pattern": "*.txt", "path": cwd_str })),
                    call("c3", "ls", json!({ "path": cwd_str })),
                    call("c4", "ls", json!({ "path": vault.to_str().unwrap() })),
                    call(
                        "c5",
                        "grep",
                        json!({ "pattern": "needle", "path": vault.to_str().unwrap() }),
                    ),
                ],
            },
            stop: StopReason::ToolCalls,
            usage: None,
        },
        done_text("done"),
    ]));
    let mut agent = Agent::new(
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
        },
        provider.clone(),
        Arc::new(ScriptedApprover::none()),
        policy,
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("search", tx, CancellationToken::new())
        .await
        .expect("turn completes without an approval prompt");

    let requests = provider.requests.lock().unwrap();
    let results: Vec<(bool, String)> = requests[1]
        .messages
        .iter()
        .filter_map(|m| match m {
            Message::Tool { content, ok, .. } => Some((*ok, content.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 5);

    // Allowed root: public content only, nothing from the denied directory.
    for (ok, content) in &results[..3] {
        assert!(ok, "{content}");
        assert!(!content.contains("TOPSECRET"), "{content}");
        assert!(!content.contains("secret.txt"), "{content}");
    }
    assert!(results[0].1.contains("public.txt:1: public needle"));
    assert!(results[1].1.contains("public.txt"));
    assert!(results[2].1.contains("public.txt") && !results[2].1.contains("vault"));

    // Denied root: refused.
    for (ok, content) in &results[3..] {
        assert!(!ok, "{content}");
        assert!(content.contains("denied"), "{content}");
    }
}
