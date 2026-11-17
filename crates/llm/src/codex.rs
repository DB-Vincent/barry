//! Provider that delegates a whole turn to the official `codex exec` CLI.
//!
//! This is not a model API client. Codex runs its own agent loop and tools
//! under its own sandbox and its own `ChatGPT` or API-key login; Barry only
//! sends the conversation as a prompt and relays the final answer. Barry's
//! policy, sandbox and audit log do not govern what Codex does inside a turn.
//! Barry's own tools are not offered to Codex.

use std::process::Stdio;

use barry_protocol::{Message, StopReason, Usage};
use futures::SinkExt;
use futures::channel::mpsc;
use futures::stream::BoxStream;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

use crate::{LlmError, LlmEvent, LlmRequest, Provider};

/// Model name that means "let Codex pick its configured default".
pub const DEFAULT_MODEL: &str = "default";

/// Longest single JSONL line accepted from the child.
const MAX_LINE: usize = 4 * 1024 * 1024;

/// A provider that runs `codex exec --json` once per turn.
#[derive(Clone)]
pub struct CodexProvider {
    model: String,
}

impl CodexProvider {
    #[must_use]
    pub fn new(model: String) -> Self {
        Self { model }
    }
}

impl Provider for CodexProvider {
    fn stream(
        &self,
        req: LlmRequest,
        cancel: CancellationToken,
    ) -> BoxStream<'static, Result<LlmEvent, LlmError>> {
        let (tx, rx) = mpsc::channel(32);
        let model = self.model.clone();
        let mut error_tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run(model, req, cancel, tx).await {
                let _ = error_tx.send(Err(e)).await;
            }
        });
        Box::pin(rx)
    }
}

async fn run(
    model: String,
    req: LlmRequest,
    cancel: CancellationToken,
    mut tx: mpsc::Sender<Result<LlmEvent, LlmError>>,
) -> Result<(), LlmError> {
    let mut command = tokio::process::Command::new("codex");
    command.args(["exec", "--json", "--sandbox", "read-only"]);
    if model != DEFAULT_MODEL {
        command.args(["-m", &model]);
    }
    // `-` reads the prompt from stdin, so a long history never hits the
    // argument size limit and never shows up in the process list.
    command
        .arg("-")
        // Use the stored login, as `barry auth login codex` does.
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_ACCESS_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|_| LlmError::Credentials)?;
    let mut stdin = child.stdin.take().ok_or(LlmError::Credentials)?;
    let stdout = child.stdout.take().ok_or(LlmError::Credentials)?;

    let prompt = build_prompt(&req.messages);
    tokio::spawn(async move {
        let _ = stdin.write_all(prompt.as_bytes()).await;
        // Dropping stdin closes it, which ends the prompt.
    });

    let mut lines = BufReader::new(stdout.take(MAX_LINE as u64 * 16)).lines();
    let mut state = CodexState::default();
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                let _ = child.kill().await;
                send(&mut tx, state.finish(Some(StopReason::Aborted))).await?;
                return Ok(());
            }
            line = lines.next_line() => match line {
                Ok(Some(line)) if line.len() <= MAX_LINE => {
                    for event in state.handle_line(&line) {
                        send(&mut tx, event).await?;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }

    let status = child.wait().await.ok();
    let failed = status.is_none_or(|s| !s.success());
    let forced = (failed && state.error.is_none() && state.text.is_empty())
        .then(|| StopReason::Error("codex exited without an answer".to_string()));
    send(&mut tx, state.finish(forced)).await?;
    Ok(())
}

async fn send(
    tx: &mut mpsc::Sender<Result<LlmEvent, LlmError>>,
    event: LlmEvent,
) -> Result<(), LlmError> {
    tx.send(Ok(event)).await.map_err(|_| LlmError::Cancelled)
}

/// Flatten the conversation into one prompt. `codex exec` is stateless per
/// call here, so the whole history goes in every time.
pub(crate) fn build_prompt(messages: &[Message]) -> String {
    let mut out = String::new();
    for message in messages {
        match message {
            Message::System { content } => {
                out.push_str(content);
                out.push_str("\n\n");
            }
            Message::User { content } => {
                out.push_str("User:\n");
                out.push_str(content);
                out.push_str("\n\n");
            }
            Message::Assistant { content, .. } => {
                if let Some(text) = content
                    && !text.is_empty()
                {
                    out.push_str("Assistant:\n");
                    out.push_str(text);
                    out.push_str("\n\n");
                }
            }
            Message::Tool { content, .. } => {
                out.push_str("Tool result:\n");
                out.push_str(content);
                out.push_str("\n\n");
            }
        }
    }
    out
}

/// Folds `codex exec --json` events into text and usage.
#[derive(Default)]
pub(crate) struct CodexState {
    pub(crate) text: String,
    usage: Option<Usage>,
    pub(crate) error: Option<String>,
}

impl CodexState {
    pub(crate) fn handle_line(&mut self, line: &str) -> Vec<LlmEvent> {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match event.get("type").and_then(Value::as_str) {
            Some("item.completed") => {
                let item = event.get("item");
                if item.and_then(|i| i.get("type")).and_then(Value::as_str) == Some("agent_message")
                    && let Some(text) = item.and_then(|i| i.get("text")).and_then(Value::as_str)
                    && !text.is_empty()
                {
                    if !self.text.is_empty() {
                        self.text.push_str("\n\n");
                    }
                    self.text.push_str(text);
                    out.push(LlmEvent::TextDelta(text.to_string()));
                }
            }
            Some("turn.completed") => {
                if let Some(usage) = event.get("usage") {
                    let field = |name: &str| usage.get(name).and_then(Value::as_u64);
                    if let (Some(input_tokens), Some(output_tokens)) =
                        (field("input_tokens"), field("output_tokens"))
                    {
                        self.usage = Some(Usage {
                            input_tokens,
                            output_tokens,
                        });
                    }
                }
            }
            // The message text is not trusted and may echo details; keep
            // only that a failure happened.
            Some("turn.failed" | "error") => {
                self.error = Some("codex reported an error".to_string());
            }
            _ => {}
        }
        out
    }

    pub(crate) fn finish(self, forced: Option<StopReason>) -> LlmEvent {
        let stop = forced
            .or(self.error.map(StopReason::Error))
            .unwrap_or(StopReason::Stop);
        LlmEvent::Done {
            message: Message::Assistant {
                content: (!self.text.is_empty()).then_some(self.text),
                reasoning: None,
                tool_calls: Vec::new(),
            },
            stop,
            usage: self.usage,
        }
    }
}
