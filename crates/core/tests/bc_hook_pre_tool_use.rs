//! Hooks (PLAN 6.5): a PreToolUse hook that exits 2 blocks the tool; a hook
//! returning deny JSON also blocks; an allowing hook lets the policy decide.
use barry_core::config::{Config, HookConfig};
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Message, StopReason, ToolCall};
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

impl Provider for RecordingProvider {
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

struct AlwaysAllow;
impl Approver for AlwaysAllow {
    fn decide(&self, _req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        Box::pin(async { ApprovalChoice::Once })
    }
}

fn done_tool(name: &str, arguments: serde_json::Value) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: None,
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: name.to_string(),
                arguments,
            }],
        },
        stop: StopReason::ToolCalls,
        usage: None,
    }
}

fn done_text(content: &str) -> LlmEvent {
    LlmEvent::Done {
        message: Message::Assistant {
            content: Some(content.to_string()),
            reasoning: None,
            tool_calls: vec![],
        },
        stop: StopReason::Stop,
        usage: None,
    }
}

fn config_with_hooks(hooks: Vec<HookConfig>) -> Config {
    Config {
        default_model: "local".to_string(),
        max_turns: 50,
        context_window: 20_000,
        sandbox_network: true,
        fs_read_deny: vec![],
        fs_protected: vec![],
        hooks,
    }
}

fn hook_block() -> HookConfig {
    HookConfig {
        matcher: "bash".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 2".to_string()],
        timeout_secs: 5,
        fail_closed: true,
    }
}

fn hook_deny_json() -> HookConfig {
    HookConfig {
        matcher: "bash".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo '{"decision":"deny","reason":"no bash"}'"#.to_string(),
        ],
        timeout_secs: 5,
        fail_closed: false,
    }
}

fn hook_allow() -> HookConfig {
    HookConfig {
        matcher: "bash".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        timeout_secs: 5,
        fail_closed: false,
    }
}

fn hook_failing(fail_closed: bool) -> HookConfig {
    HookConfig {
        matcher: "bash".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()],
        timeout_secs: 5,
        fail_closed,
    }
}

/// An approver that records the requests it sees and always answers the same.
struct RecordingApprover {
    requests: Mutex<Vec<ApprovalRequest>>,
    choice: ApprovalChoice,
}

impl RecordingApprover {
    fn new(choice: ApprovalChoice) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            choice,
        }
    }
}

impl Approver for RecordingApprover {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        self.requests.lock().unwrap().push(req.clone());
        let choice = self.choice.clone();
        Box::pin(async move { choice })
    }
}

fn requests_of(provider: &Arc<RecordingProvider>) -> Vec<LlmRequest> {
    provider.requests.lock().unwrap().clone()
}

fn last_tool_content(reqs: &[LlmRequest]) -> Option<String> {
    let last = reqs.last()?;
    last.messages.iter().rev().find_map(|m| match m {
        Message::Tool { content, .. } => Some(content.clone()),
        _ => None,
    })
}

#[tokio::test]
async fn hook_exit_2_blocks_the_tool() {
    let config = config_with_hooks(vec![hook_block()]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));

    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hook blocked"),
        "exit-2 hook should block the tool: {content}"
    );
}

#[tokio::test]
async fn hook_deny_json_blocks_the_tool() {
    let config = config_with_hooks(vec![hook_deny_json()]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));

    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hook denied") || content.contains("no bash"),
        "deny-JSON hook should block the tool: {content}"
    );
}

#[tokio::test]
async fn hook_allow_lets_policy_decide() {
    // No policy: bash runs unsandboxed; the allowing hook does not block it.
    let config = config_with_hooks(vec![hook_allow()]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));

    let mut agent =
        Agent::new(config, provider, Arc::new(AlwaysAllow), None).expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    let result = agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(result, StopReason::Stop);
}

/// A PreToolUse hook that rewrites the tool input must affect `write`.
#[tokio::test]
async fn hook_updated_input_rewrites_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("from-hook.txt");
    let rewritten = format!(
        r#"{{"updated_input":{{"path":"{}","content":"from hook"}}}}"#,
        target.display()
    );
    let hook = HookConfig {
        matcher: "write".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{rewritten}'"),
        ],
        timeout_secs: 5,
        fail_closed: false,
    };

    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool(
            "write",
            json!({ "path": dir.path().join("original.txt"), "content": "original" }),
        ),
        done_text("done"),
    ]));
    let mut agent = Agent::new(
        config_with_hooks(vec![hook]),
        provider,
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("write the file", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    assert_eq!(
        std::fs::read_to_string(&target).expect("hook-chosen file exists"),
        "from hook"
    );
    assert!(
        !dir.path().join("original.txt").exists(),
        "the original path must not be used"
    );
}

/// A PreToolUse hook that rewrites the tool input must affect `edit`.
#[tokio::test]
async fn hook_updated_input_rewrites_edit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file.txt");
    std::fs::write(&file, "old\n").expect("seed file");
    let rewritten = format!(
        r#"{{"updated_input":{{"path":"{}","old_string":"old","new_string":"new"}}}}"#,
        file.display()
    );
    let hook = HookConfig {
        matcher: "edit".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo '{rewritten}'"),
        ],
        timeout_secs: 5,
        fail_closed: false,
    };

    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool(
            "edit",
            json!({ "path": file, "old_string": "missing", "new_string": "x" }),
        ),
        done_text("done"),
    ]));
    let mut agent = Agent::new(
        config_with_hooks(vec![hook]),
        provider,
        Arc::new(AlwaysAllow),
        None,
    )
    .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("edit the file", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    assert_eq!(
        std::fs::read_to_string(&file).expect("file readable"),
        "new\n",
        "the hook's old_string/new_string must be the edit that runs"
    );
}

/// `fail_closed` turns a hook failure (non-zero exit) into a block.
#[tokio::test]
async fn hook_fail_closed_blocks_on_failure() {
    let config = config_with_hooks(vec![hook_failing(true)]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));
    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hook blocked"),
        "fail_closed hook should block the tool: {content}"
    );
}

/// Without `fail_closed`, the same failure only warns and the tool runs.
#[tokio::test]
async fn hook_warns_on_failure_when_not_fail_closed() {
    let config = config_with_hooks(vec![hook_failing(false)]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));
    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hi"),
        "a non-fail-closed hook failure must not block the tool: {content}"
    );
}

/// Unparseable stdout is a hook failure, so `fail_closed` blocks on it.
#[tokio::test]
async fn hook_fail_closed_blocks_on_invalid_json() {
    let hook = HookConfig {
        matcher: "bash".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo not-json".to_string(),
        ],
        timeout_secs: 5,
        fail_closed: true,
    };
    let config = config_with_hooks(vec![hook]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));
    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hook blocked"),
        "invalid hook output should block under fail_closed: {content}"
    );
}

/// A timed-out hook is killed: it must not touch the filesystem after the turn.
#[tokio::test]
async fn hook_timeout_kills_the_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("survived");
    let hook = HookConfig {
        matcher: "bash".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("sleep 1.5; touch {}", marker.display()),
        ],
        timeout_secs: 1,
        fail_closed: true,
    };
    let config = config_with_hooks(vec![hook]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));
    let mut agent = Agent::new(config, provider.clone(), Arc::new(AlwaysAllow), None)
        .expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("hook blocked"),
        "a timed-out fail_closed hook should block the tool: {content}"
    );

    // The hook would touch the marker at 1.5s; after the 1s timeout plus this
    // wait it must be dead.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        !marker.exists(),
        "the timed-out hook process was not killed"
    );
}

/// `Ask` is a question for the user, not a silent allow.
#[tokio::test]
async fn hook_ask_is_routed_to_the_approver() {
    let hook = HookConfig {
        matcher: "bash".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo '{"decision":"ask","reason":"please confirm"}'"#.to_string(),
        ],
        timeout_secs: 5,
        fail_closed: false,
    };
    let config = config_with_hooks(vec![hook]);
    let provider = Arc::new(RecordingProvider::new(vec![
        done_tool("bash", json!({ "command": "echo hi" })),
        done_text("acknowledged"),
    ]));
    let approver = Arc::new(RecordingApprover::new(ApprovalChoice::Deny));
    let mut agent =
        Agent::new(config, provider.clone(), approver.clone(), None).expect("agent constructs");

    let (tx, _rx) = mpsc::channel(32);
    agent
        .run_turn("run bash", tx, CancellationToken::new())
        .await
        .expect("turn completes");

    let asked = approver.requests.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "the hook's ask should reach the approver");
    assert_eq!(asked[0].reason, "please confirm");

    let reqs = requests_of(&provider);
    let content = last_tool_content(&reqs).expect("a tool result");
    assert!(
        content.contains("denied by user"),
        "the approver's denial must be final: {content}"
    );
}

/// An empty hook command is a config error, not a panic.
#[test]
fn hook_with_empty_command_is_rejected() {
    let config = config_with_hooks(vec![HookConfig {
        matcher: "bash".to_string(),
        command: vec![],
        timeout_secs: 5,
        fail_closed: false,
    }]);
    let provider = Arc::new(RecordingProvider::new(vec![]));
    let result = Agent::new(config, provider, Arc::new(AlwaysAllow), None);
    assert!(result.is_err(), "an empty hook command must be rejected");
}
