#![allow(clippy::unwrap_used, clippy::expect_used)]

/// `edit` supports `replace_all` and multiple edits per call, answers with a
/// unified diff, and refuses a file that was not read first or that changed
/// since it was read.
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{Message, StopReason, ToolCall};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

struct Provider {
    replies: Mutex<VecDeque<LlmEvent>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl barry_llm::Provider for Provider {
    fn stream(
        &self,
        req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
        self.requests.lock().unwrap().push(req);
        let reply = self.replies.lock().unwrap().pop_front().expect("reply");
        stream::iter(vec![Ok(reply)]).boxed()
    }
}

struct Yes;

impl Approver for Yes {
    fn decide(
        &self,
        _req: &barry_protocol::ApprovalRequest,
    ) -> BoxFuture<'_, barry_protocol::ApprovalChoice> {
        Box::pin(async { barry_protocol::ApprovalChoice::Once })
    }
}

fn call(name: &str, arguments: Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "c".to_string(),
                name: name.to_string(),
                arguments,
            }],
        },
        stop: StopReason::ToolCalls,
        usage: None,
    }
}

fn text(t: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: Some(t.to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
        stop: StopReason::Stop,
        usage: None,
    }
}

/// A policy whose working directory is the temp dir, so the fixtures are
/// writable without a prompt.
fn policy() -> barry_policy::Policy {
    barry_policy::Policy::new(barry_policy::PolicyConfig {
        cwd: std::env::temp_dir(),
        home: std::env::temp_dir().join("barry-test-policy-home"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

/// Runs the scripted tool calls and returns `(ok, content)` per call.
async fn run(calls: Vec<LlmEvent>) -> Vec<(bool, String)> {
    let mut replies = calls;
    replies.push(text("done"));
    let provider = Arc::new(Provider {
        replies: Mutex::new(replies.into()),
        requests: Mutex::new(Vec::new()),
    });
    let mut agent = Agent::new(
        barry_core::config::Config {
            default_model: "test".to_string(),
            max_turns: 20,
            context_window: 32_768,
            sandbox_network: true,
            sandbox_unsandboxed: true,
            redact_tool_output: false,
            fs_read_deny: vec![],
            fs_protected: vec![],
            rules: vec![],
            hooks: vec![],
            budgets: barry_core::budget::Budgets::default(),
        },
        provider.clone(),
        Arc::new(Yes),
        policy(),
    )
    .expect("agent constructs");
    let (tx, _rx) = mpsc::channel(256);
    agent
        .run_turn("go", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    let requests = provider.requests.lock().unwrap();
    requests
        .last()
        .unwrap()
        .messages
        .iter()
        .filter_map(|m| match m {
            Message::Tool { content, ok, .. } => Some((*ok, content.clone())),
            _ => None,
        })
        .collect()
}

fn fixture(contents: &str) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f.txt");
    std::fs::write(&file, contents).unwrap();
    let path = file.to_str().unwrap().to_string();
    (dir, file, path)
}

#[tokio::test]
async fn edit_without_a_prior_read_is_refused() {
    let (_dir, file, path) = fixture("alpha\n");
    let results = run(vec![call(
        "edit",
        json!({"path": path, "old_string": "alpha", "new_string": "beta"}),
    )])
    .await;
    assert!(!results[0].0);
    assert!(
        results[0].1.contains("has not been read"),
        "{}",
        results[0].1
    );
    assert_eq!(std::fs::read_to_string(file).unwrap(), "alpha\n");
}

#[tokio::test]
async fn edit_after_the_file_changed_is_refused() {
    let (_dir, file, path) = fixture("alpha\n");
    let results = run(vec![
        call("read", json!({"path": path})),
        call(
            "bash",
            json!({"command": format!("echo extra >> '{path}'")}),
        ),
        call(
            "edit",
            json!({"path": path, "old_string": "alpha", "new_string": "beta"}),
        ),
    ])
    .await;
    assert!(results[0].0 && results[1].0, "{results:?}");
    assert!(!results[2].0);
    assert!(results[2].1.contains("changed since"), "{}", results[2].1);
    assert_eq!(std::fs::read_to_string(file).unwrap(), "alpha\nextra\n");
}

#[tokio::test]
async fn edit_returns_a_unified_diff_and_allows_a_second_edit_without_rereading() {
    let (_dir, file, path) = fixture("one\ntwo\nthree\n");
    let results = run(vec![
        call("read", json!({"path": path})),
        call(
            "edit",
            json!({"path": path, "old_string": "two", "new_string": "2"}),
        ),
        call(
            "edit",
            json!({"path": path, "old_string": "three", "new_string": "3"}),
        ),
    ])
    .await;
    assert!(results.iter().all(|(ok, _)| *ok), "{results:?}");
    assert!(results[1].1.contains("@@ -1,3 +1,3 @@"), "{}", results[1].1);
    assert!(results[1].1.contains("-two\n+2\n"), "{}", results[1].1);
    assert!(
        !results[1].1.contains("old_string"),
        "no echo of arguments: {}",
        results[1].1
    );
    assert_eq!(std::fs::read_to_string(file).unwrap(), "one\n2\n3\n");
}

#[tokio::test]
async fn replace_all_replaces_every_occurrence() {
    let (_dir, file, path) = fixture("x x x\n");
    let results = run(vec![
        call("read", json!({"path": path})),
        call(
            "edit",
            json!({"path": path, "old_string": "x", "new_string": "y"}),
        ),
        call(
            "edit",
            json!({"path": path, "old_string": "x", "new_string": "y", "replace_all": true}),
        ),
    ])
    .await;
    assert!(!results[1].0, "ambiguous without replace_all: {results:?}");
    assert!(results[1].1.contains("found 3 matches"));
    assert!(results[2].0);
    assert!(results[2].1.contains("3 replacements"), "{}", results[2].1);
    assert_eq!(std::fs::read_to_string(file).unwrap(), "y y y\n");
}

#[tokio::test]
async fn multi_edit_applies_in_order_and_is_all_or_nothing() {
    let (_dir, file, path) = fixture("a\nb\n");
    let results = run(vec![
        call("read", json!({"path": path})),
        // The second edit fails, so the first must not be written.
        call(
            "edit",
            json!({"path": path, "edits": [
                {"old_string": "a", "new_string": "A"},
                {"old_string": "zzz", "new_string": "Z"}
            ]}),
        ),
        call(
            "edit",
            json!({"path": path, "edits": [
                {"old_string": "a", "new_string": "A"},
                {"old_string": "A", "new_string": "AA"},
                {"old_string": "b", "new_string": "B"}
            ]}),
        ),
    ])
    .await;
    assert!(!results[1].0);
    assert!(
        results[1].1.contains("edit 2: no matches"),
        "{}",
        results[1].1
    );
    assert!(results[2].0, "{}", results[2].1);
    assert!(results[2].1.contains("3 replacements"));
    assert_eq!(std::fs::read_to_string(file).unwrap(), "AA\nB\n");
}

#[tokio::test]
async fn a_file_the_model_wrote_can_be_edited_without_a_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.txt").to_str().unwrap().to_string();
    let results = run(vec![
        call("write", json!({"path": path, "content": "hello\n"})),
        call(
            "edit",
            json!({"path": path, "old_string": "hello", "new_string": "bye"}),
        ),
    ])
    .await;
    assert!(results.iter().all(|(ok, _)| *ok), "{results:?}");
    assert_eq!(std::fs::read_to_string(path).unwrap(), "bye\n");
}
