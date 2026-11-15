#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Budgets: a run that exceeds a configured limit stops with a distinct
/// `StopReason::BudgetExceeded`, tells the user why, and does not run further
/// tool calls.
use barry_core::budget::Budgets;
use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{LlmEvent, LlmRequest};
use barry_protocol::{BudgetKind, Event, Message, StopReason, ToolCall, Usage};
use futures::channel::mpsc;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Always answers with one bash call, reporting fixed usage per request.
struct ToolProvider {
    command: String,
    usage: Option<Usage>,
    requests: Mutex<usize>,
}

impl ToolProvider {
    fn new(command: &str, usage: Option<Usage>) -> Arc<Self> {
        Arc::new(Self {
            command: command.to_string(),
            usage,
            requests: Mutex::new(0),
        })
    }
}

impl barry_llm::Provider for ToolProvider {
    fn stream(
        &self,
        _req: LlmRequest,
        _cancel: CancellationToken,
    ) -> futures::stream::BoxStream<'static, Result<LlmEvent, barry_llm::LlmError>> {
        let mut requests = self.requests.lock().unwrap();
        *requests += 1;
        let reply = LlmEvent::Done {
            message: Message::Assistant {
                content: None,
                reasoning: None,
                tool_calls: vec![ToolCall {
                    id: format!("call_{}", *requests),
                    name: "bash".to_string(),
                    arguments: json!({ "command": self.command }),
                }],
            },
            stop: StopReason::ToolCalls,
            usage: self.usage.clone(),
        };
        stream::iter(vec![Ok(reply)]).boxed()
    }
}

struct AllowAll;
impl Approver for AllowAll {
    fn decide(
        &self,
        _req: &barry_protocol::ApprovalRequest,
    ) -> BoxFuture<'_, barry_protocol::ApprovalChoice> {
        Box::pin(async { barry_protocol::ApprovalChoice::Once })
    }
}

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

fn agent(provider: Arc<ToolProvider>, budgets: Budgets) -> Agent {
    Agent::new(
        Config {
            default_model: "test".to_string(),
            max_turns: 20,
            context_window: 1_000_000,
            sandbox_network: true,
            sandbox_unsandboxed: true,
            redact_tool_output: false,
            fs_read_deny: vec![],
            fs_protected: vec![],
            rules: vec![],
            hooks: vec![],
            budgets,
        },
        provider,
        Arc::new(AllowAll),
        policy(),
    )
    .expect("agent constructs")
}

async fn run(agent: &mut Agent) -> (StopReason, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel(256);
    let stop = agent
        .run_turn("go", tx, CancellationToken::new())
        .await
        .expect("a budget stop is not an error");
    let mut events = Vec::new();
    while let Some(event) = rx.next().await {
        events.push(event);
    }
    (stop, events)
}

fn notices(events: &[Event]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Notice(text) => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn tool_results(events: &[Event]) -> Vec<bool> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::ToolFinished { ok, .. } => Some(*ok),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn token_budget_stops_the_run_and_skips_the_pending_tool_call() {
    let provider = ToolProvider::new(
        "echo hi",
        Some(Usage {
            input_tokens: 40,
            output_tokens: 20,
        }),
    );
    let mut agent = agent(
        provider.clone(),
        Budgets {
            max_total_tokens: Some(100),
            ..Budgets::default()
        },
    );
    let (stop, events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::BudgetExceeded(BudgetKind::Tokens));
    // 60 tokens after request 1 (within budget), 120 after request 2.
    assert_eq!(*provider.requests.lock().unwrap(), 2);
    // The first call ran; the second was answered but not executed.
    assert_eq!(tool_results(&events), vec![true, false]);
    let notes = notices(&events);
    assert_eq!(notes.len(), 1, "{events:?}");
    assert!(notes[0].contains("token budget exceeded"), "{notes:?}");
    match events.last() {
        Some(Event::TurnFinished {
            stop: StopReason::BudgetExceeded(BudgetKind::Tokens),
            usage: Some(usage),
        }) => assert_eq!(usage.input_tokens + usage.output_tokens, 120),
        other => panic!("expected TurnFinished with usage, got {other:?}"),
    }
}

#[tokio::test]
async fn estimated_tokens_apply_when_the_provider_reports_no_usage() {
    let provider = ToolProvider::new("echo hi", None);
    let mut agent = agent(
        provider.clone(),
        Budgets {
            // The system prompt alone is far larger than this.
            max_total_tokens: Some(10),
            ..Budgets::default()
        },
    );
    let (stop, events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::BudgetExceeded(BudgetKind::Tokens));
    assert_eq!(*provider.requests.lock().unwrap(), 1);
    assert_eq!(tool_results(&events), vec![false], "tool must not run");
}

#[tokio::test]
async fn cost_budget_uses_the_configured_prices() {
    let provider = ToolProvider::new(
        "echo hi",
        Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
        }),
    );
    let mut agent = agent(
        provider,
        Budgets {
            max_cost_usd: Some(0.5),
            price_input_per_mtok: Some(1.0),
            price_output_per_mtok: Some(2.0),
            ..Budgets::default()
        },
    );
    let (stop, events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::BudgetExceeded(BudgetKind::Cost));
    assert!(notices(&events)[0].contains("cost budget exceeded"));
}

#[tokio::test]
async fn bash_time_budget_stops_after_the_command_that_exceeds_it() {
    let provider = ToolProvider::new("sleep 1", None);
    let mut agent = agent(
        provider.clone(),
        Budgets {
            max_bash_secs: Some(0),
            ..Budgets::default()
        },
    );
    let (stop, events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::BudgetExceeded(BudgetKind::BashTime));
    assert_eq!(*provider.requests.lock().unwrap(), 1);
    assert_eq!(tool_results(&events), vec![true], "the command did run");
}

#[tokio::test]
async fn wall_clock_budget_stops_before_the_next_request() {
    let provider = ToolProvider::new("sleep 1.2", None);
    let mut agent = agent(
        provider.clone(),
        Budgets {
            max_wall_secs: Some(1),
            ..Budgets::default()
        },
    );
    let (stop, _events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::BudgetExceeded(BudgetKind::WallClock));
    assert_eq!(*provider.requests.lock().unwrap(), 1);
}

#[tokio::test]
async fn no_budget_means_the_turn_limit_still_applies() {
    let provider = ToolProvider::new("true", None);
    let mut agent = agent(provider.clone(), Budgets::default());
    let (stop, _events) = run(&mut agent).await;

    assert_eq!(stop, StopReason::Stop);
    assert_eq!(*provider.requests.lock().unwrap(), 20);
}

#[test]
fn a_cost_limit_without_prices_is_rejected_at_construction() {
    let result = Agent::new(
        Config {
            budgets: Budgets {
                max_cost_usd: Some(1.0),
                ..Budgets::default()
            },
            ..Config::default()
        },
        ToolProvider::new("true", None),
        Arc::new(AllowAll),
        policy(),
    );
    assert!(result.is_err());
}
