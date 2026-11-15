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
        budgets: Default::default(),
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
