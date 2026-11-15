//! The turn loop: request, stream, dispatch tools, feed results back.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use barry_llm::{LlmEvent, LlmRequest, Provider};
use barry_policy::Policy;
use barry_protocol::{DecidedBy, Decision, Event, Message, StopReason, ToolCall};
use futures::channel::mpsc;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::hooks::Hook;
use crate::prompt::{system_prompt, PromptContext};
use crate::session::{self, decided_by_label, decision_label, EntryKind, SessionError, SessionLog};
use crate::tools::{execute_tool, tool_specs, ToolResult};
use crate::{Approver, CoreError};

/// Wraps a tool result for the model (PLAN 5). Kept here rather than in
/// `tools` because it is a property of the message, not of the tool.
fn wrap_tool_output(tool: &str, ok: bool, content: &str) -> String {
    format!("<tool_output tool=\"{tool}\" ok=\"{ok}\">\n{content}\n</tool_output>")
}

/// The main agent that drives the turn loop.
///
/// `history` outlives a single turn: the M2 REPL and BC-2.9 both need the
/// next request to carry what happened in the previous one (notably the
/// "interrupted by user" tool result of a cancelled command). The system
/// prompt is not stored; it is prepended to every request.
pub struct Agent {
    pub(crate) cfg: Config,
    provider: Arc<dyn Provider>,
    pub(crate) approver: Arc<dyn Approver>,
    policy: Option<Policy>,
    history: Vec<Message>,
    /// Built once so every request carries the same prefix (PLAN 5.2).
    system_prompt: String,
    /// Context window (tokens) used for compaction heuristics.
    context_window: u64,
    /// Number of compactions performed in the current `run_turn` (PLAN 6.4).
    compactions: u64,
    /// Audit log, when a session is being recorded (PLAN 6.7).
    session: Option<SessionLog>,
    /// Whether a session-log write failure has already been reported.
    session_warned: bool,
    /// Compiled PreToolUse hooks (PLAN 6.5).
    hooks: Vec<Hook>,
}

impl Agent {
    pub fn new(
        cfg: crate::config::Config,
        provider: Arc<dyn Provider>,
        approver: Arc<dyn Approver>,
        policy: Option<Policy>,
    ) -> Result<Self, CoreError> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let date = crate::prompt::today();

        // PLAN 6.3: assemble the AGENTS.md and skills sections for the prompt.
        let git_root = find_git_root(&cwd);
        let agents_md_section = crate::context::instructions_section(&git_root, &cwd);
        let global_skills = std::env::var("HOME").map_or_else(
            |_| PathBuf::from(".config/barry/skills"),
            |home| PathBuf::from(home).join(".config/barry/skills"),
        );
        let project_skills = git_root.join(".barry/skills");
        let skills_section = crate::context::skills_section(&global_skills, &project_skills);

        let system_prompt = system_prompt(&PromptContext {
            cwd: &cwd,
            os: std::env::consts::OS,
            date: &date,
            agents_md_section: &agents_md_section,
            skills_section: &skills_section,
        });

        let context_window = cfg.context_window;
        let hooks: Vec<Hook> = cfg
            .hooks
            .iter()
            .cloned()
            .map(Hook::new)
            .collect::<Result<Vec<Hook>, CoreError>>()?;
        Ok(Self {
            cfg,
            provider,
            approver,
            policy,
            history: Vec::new(),
            system_prompt,
            context_window,
            compactions: 0,
            session: None,
            session_warned: false,
            hooks,
        })
    }

    /// Attach an audit log and record `session_start` (PLAN 6.7).
    #[must_use]
    pub fn with_session_log(mut self, mut log: SessionLog) -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        if let Err(err) = log.append(EntryKind::SessionStart {
            cwd: cwd.display().to_string(),
            model: self.cfg.default_model.clone(),
            barry_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_sha256: session::policy_fingerprint(self.policy.as_ref()),
        }) {
            self.session_warned = true;
            eprintln!("warning: session log write failed: {err}");
        }
        self.session = Some(log);
        self
    }

    /// Rebuild an agent from a session log (BC-5.5, PLAN 6.7).
    pub fn resume(
        cfg: crate::config::Config,
        provider: Arc<dyn Provider>,
        approver: Arc<dyn Approver>,
        policy: Option<Policy>,
        session_file: &Path,
    ) -> Result<Self, CoreError> {
        // Never extend a chain that does not verify: the audit trail is the
        // point of resuming from it.
        let report = session::verify(session_file).map_err(|err| session_error(&err))?;
        if let Some(line) = report.broken_at {
            return Err(CoreError::Session(format!(
                "session log is broken at line {line}"
            )));
        }
        let history = session::replay_history(session_file).map_err(|err| session_error(&err))?;
        let log = SessionLog::open_append(session_file).map_err(|err| session_error(&err))?;

        let mut agent = Self::new(cfg, provider, approver, policy)?;
        agent.history = history;
        agent.session = Some(log);
        Ok(agent)
    }

    /// Append one entry, warning once if the log becomes unwritable. The turn
    /// continues: a full disk must not block the user's work, but it must not
    /// be silent either.
    fn log(&mut self, kind: EntryKind) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if let Err(err) = session.append(kind) {
            if !self.session_warned {
                self.session_warned = true;
                eprintln!("warning: session log write failed: {err}");
            }
        }
    }

    /// Record the decision for a call the agent never handed to `execute_tool`
    /// (a cancelled call). Executed calls log their own decision before
    /// running (BC-5.1).
    fn log_decision(&mut self, call: &ToolCall, decision: &Decision, decided_by: &DecidedBy) {
        self.log(EntryKind::ToolDecision {
            call_id: call.id.clone(),
            tool: call.name.clone(),
            input: call.arguments.clone(),
            decision: decision_label(decision),
            decided_by: decided_by_label(decided_by),
        });
    }

    /// Record the outcome after a tool finishes.
    fn log_result(&mut self, call: &ToolCall, result: &ToolResult) {
        self.log(EntryKind::ToolResult {
            call_id: call.id.clone(),
            ok: result.ok,
            bytes: result.content.len(),
            exit_code: result.exit_code,
        });
    }

    /// Total bytes of readable content in the conversation history.
    fn history_bytes(&self) -> u64 {
        self.history.iter().map(message_bytes).sum()
    }

    /// Rough token estimate: bytes / 4 (PLAN 6.4).
    fn estimate_tokens(&self) -> u64 {
        self.history_bytes() / 4
    }

    /// Compaction threshold: context window minus a safety reserve.
    fn compaction_threshold(&self) -> u64 {
        self.context_window.saturating_sub(16_384)
    }

    /// Replace the content of older Tool messages with a clearance marker,
    /// keeping the newest ~20,000 tokens of tool output (PLAN 6.4, step 1).
    fn clear_old_tool_outputs(&mut self) {
        const KEEP_TOKENS: u64 = 20_000;
        let tool_indices: Vec<(usize, u64)> = self
            .history
            .iter()
            .enumerate()
            .filter_map(|(i, m)| match m {
                Message::Tool { content, .. } => Some((i, content.len() as u64)),
                _ => None,
            })
            .collect();
        let tool_tokens: u64 = tool_indices.iter().map(|(_, b)| b / 4).sum();
        if tool_tokens <= KEEP_TOKENS {
            return;
        }
        let mut remaining = tool_tokens;
        for (i, bytes) in tool_indices {
            if remaining <= KEEP_TOKENS {
                break;
            }
            remaining -= bytes / 4;
            if let Message::Tool { content, .. } = &mut self.history[i] {
                *content = "[output cleared to save context]".to_string();
                self.log(EntryKind::Notice {
                    text: "cleared old tool output to save context".to_string(),
                });
            }
        }
    }

    /// Run compaction before building an LLM request (PLAN 6.4).
    /// Returns `true` if a compaction was performed this turn.
    async fn maybe_compact(&mut self, events: &mut mpsc::Sender<Event>) -> Result<bool, CoreError> {
        if self.estimate_tokens() <= self.compaction_threshold() {
            return Ok(false);
        }

        // Step 1: clear old tool outputs.
        self.clear_old_tool_outputs();
        if self.estimate_tokens() <= self.compaction_threshold() {
            return Ok(true);
        }

        // Step 2: summarise (PLAN 6.4, steps 2-3).
        if self.compactions >= 3 {
            events
                .send(Event::Notice("context full".to_string()))
                .await
                .map_err(|_| CoreError::ChannelClosed)?;
            return Ok(false);
        }
        self.summarise().await?;
        self.compactions += 1;
        Ok(true)
    }

    /// Send one non-streaming summarisation request and replace the history
    /// with a single summary user message (PLAN 6.4, step 3).
    async fn summarise(&mut self) -> Result<(), CoreError> {
        let mut messages: Vec<Message> = vec![Message::System {
            content: self.system_prompt.clone(),
        }];
        messages.extend(self.history.iter().cloned());
        messages.push(Message::User {
            content: "Summarise the conversation so far for continuing the task: goals, \
                decisions, files changed, current state, open problems. Be concise."
                .to_string(),
        });

        let req = LlmRequest {
            messages,
            tools: vec![],
        };
        let mut stream = self.provider.stream(req, CancellationToken::new());
        let mut summary = String::new();
        while let Some(event) = stream.next().await {
            let event = event.map_err(|e| CoreError::Provider(e.to_string()))?;
            if let LlmEvent::Done { message, .. } = event {
                if let Message::User { content } | Message::Tool { content, .. } = message {
                    summary = content;
                } else if let Message::Assistant {
                    content: Some(text),
                    ..
                } = message
                {
                    summary = text;
                }
                break;
            }
        }

        let mut replaced = Vec::new();
        replaced.push(Message::User {
            content: format!("[Summary of earlier conversation]\n{summary}"),
        });
        // PLAN 6.6: raw messages stay in the log; record what was compacted.
        self.log(EntryKind::Compaction {
            removed_seq_range: [0, self.history.len() as u64],
            summary: summary.clone(),
        });
        self.history = replaced;

        self.log(EntryKind::Notice {
            text: "summarised earlier conversation to save context".to_string(),
        });
        Ok(())
    }

    /// Force compaction of the conversation context (PLAN 6.7 `/compact`).
    /// Runs the summarisation step if there is anything to compact, replacing
    /// the history with a single summary message and writing a `compaction`
    /// log entry. Returns `true` when a compaction was performed.
    pub async fn compact(&mut self) -> Result<bool, CoreError> {
        if self.history.is_empty() {
            return Ok(false);
        }
        self.summarise().await?;
        Ok(true)
    }

    pub async fn run_turn(
        &mut self,
        user_input: &str,
        mut events: mpsc::Sender<Event>,
        cancel: CancellationToken,
    ) -> Result<StopReason, CoreError> {
        let user_message = Message::User {
            content: user_input.to_string(),
        };
        self.history.push(user_message.clone());
        self.log(EntryKind::Message {
            message: user_message,
        });

        let tools = tool_specs(); // read, write, edit, bash, agent

        for _turn in 0..self.cfg.max_turns {
            events
                .send(Event::TurnStarted)
                .await
                .map_err(|_| CoreError::ChannelClosed)?;

            let mut messages = Vec::with_capacity(self.history.len() + 1);
            // PLAN 6.4: compact the context before building the request.
            self.maybe_compact(&mut events).await?;
            messages.push(Message::System {
                content: self.system_prompt.clone(),
            });
            messages.extend(self.history.iter().cloned());

            let req = LlmRequest {
                messages,
                tools: tools.clone(),
            };
            let mut stream = self.provider.stream(req, cancel.clone());

            while let Some(event) = stream.next().await {
                let event = event.map_err(|e| CoreError::Provider(e.to_string()))?;

                match event {
                    LlmEvent::TextDelta(s) => {
                        events
                            .send(Event::TextDelta(s))
                            .await
                            .map_err(|_| CoreError::ChannelClosed)?;
                    }
                    LlmEvent::ReasoningDelta(s) => {
                        events
                            .send(Event::ReasoningDelta(s))
                            .await
                            .map_err(|_| CoreError::ChannelClosed)?;
                    }
                    LlmEvent::Done { message, stop, .. } => {
                        self.history.push(message.clone());
                        self.log(EntryKind::Message {
                            message: message.clone(),
                        });

                        match stop {
                            StopReason::Stop => {
                                events
                                    .send(Event::TurnFinished { stop, usage: None })
                                    .await
                                    .map_err(|_| CoreError::ChannelClosed)?;
                                return Ok(StopReason::Stop);
                            }
                            StopReason::ToolCalls => {
                                let tool_calls = match &message {
                                    Message::Assistant { tool_calls, .. } => tool_calls.clone(),
                                    _ => Vec::new(),
                                };
                                for call in &tool_calls {
                                    // Once a cancel lands, the remaining calls are not
                                    // executed, but each still gets a Tool message: the
                                    // model rejects a reply whose call ids are not all
                                    // answered, so the history must stay well formed.
                                    if cancel.is_cancelled() {
                                        events
                                            .send(Event::ToolFinished {
                                                id: call.id.clone(),
                                                ok: false,
                                                display: "interrupted by user".to_string(),
                                            })
                                            .await
                                            .map_err(|_| CoreError::ChannelClosed)?;
                                        let interrupted = ToolResult::interrupted();
                                        self.log_decision(
                                            call,
                                            &Decision::Deny {
                                                reason: "interrupted by user".to_string(),
                                            },
                                            &DecidedBy::User,
                                        );
                                        self.log_result(call, &interrupted);
                                        let tool_message = Message::Tool {
                                            tool_call_id: call.id.clone(),
                                            content: wrap_tool_output(
                                                &call.name,
                                                false,
                                                "interrupted by user",
                                            ),
                                            ok: false,
                                        };
                                        self.history.push(tool_message.clone());
                                        self.log(EntryKind::Message {
                                            message: tool_message,
                                        });
                                        continue;
                                    }

                                    let display = format!("{} {}", call.name, call.arguments);
                                    events
                                        .send(Event::ToolStarted {
                                            id: call.id.clone(),
                                            name: call.name.clone(),
                                            display,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;

                                    // A tool error is a result, not a turn failure.
                                    let result = execute_tool(
                                        call,
                                        &self.cfg,
                                        &mut self.policy,
                                        &self.approver,
                                        &cancel,
                                        self.session.as_mut(),
                                        &self.hooks,
                                    )
                                    .await
                                    .unwrap_or_else(|err| ToolResult::internal_error(&err));

                                    events
                                        .send(Event::ToolFinished {
                                            id: call.id.clone(),
                                            ok: result.ok,
                                            display: result.display.clone(),
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;

                                    self.log_result(call, &result);

                                    // PLAN 5: every result is wrapped, so the model can
                                    // tell tool output apart from conversation text.
                                    let tool_message = Message::Tool {
                                        tool_call_id: call.id.clone(),
                                        content: wrap_tool_output(
                                            &call.name,
                                            result.ok,
                                            &result.content,
                                        ),
                                        ok: result.ok,
                                    };
                                    self.history.push(tool_message.clone());
                                    self.log(EntryKind::Message {
                                        message: tool_message,
                                    });
                                }

                                if cancel.is_cancelled() {
                                    events
                                        .send(Event::TurnFinished {
                                            stop: StopReason::Aborted,
                                            usage: None,
                                        })
                                        .await
                                        .map_err(|_| CoreError::ChannelClosed)?;
                                    return Ok(StopReason::Aborted);
                                }
                                // loop continues: call LLM again with tool results
                            }
                            StopReason::Aborted => {
                                events
                                    .send(Event::TurnFinished { stop, usage: None })
                                    .await
                                    .map_err(|_| CoreError::ChannelClosed)?;
                                return Ok(StopReason::Aborted);
                            }
                            _ => return Err(CoreError::Provider("unexpected stop reason".into())),
                        }
                    }
                }

                if cancel.is_cancelled() {
                    return Ok(StopReason::Aborted);
                }
            }
        }

        // PLAN 5: the limit is a normal stop with a notice, not an error.
        // The CLI turns this notice into exit code 3 (BC-2.10).
        let notice = "turn limit reached".to_string();
        events
            .send(Event::Notice(notice.clone()))
            .await
            .map_err(|_| CoreError::ChannelClosed)?;
        self.log(EntryKind::Notice { text: notice });
        events
            .send(Event::TurnFinished {
                stop: StopReason::Stop,
                usage: None,
            })
            .await
            .map_err(|_| CoreError::ChannelClosed)?;
        Ok(StopReason::Stop)
    }

    /// The audit log path, when this agent is recording a session.
    pub fn session_path(&self) -> Option<&Path> {
        self.session.as_ref().map(SessionLog::path)
    }

    /// Directories granted this session (PLAN 6.9 `/grants`).
    #[must_use]
    pub fn grants(&self) -> Vec<std::path::PathBuf> {
        self.policy
            .as_ref()
            .map(|policy| policy.grants().to_vec())
            .unwrap_or_default()
    }

    /// Replace the provider after `/model` changes the model id. History and
    /// the system prompt stay as they are.
    pub fn set_provider(&mut self, provider: Arc<dyn Provider>) {
        self.provider = provider;
    }
}

fn session_error(err: &SessionError) -> CoreError {
    CoreError::Session(err.to_string())
}

/// Readable bytes of one message (content plus tool-call arguments).
fn message_bytes(m: &Message) -> u64 {
    match m {
        Message::System { content } => content.len() as u64,
        Message::User { content } => content.len() as u64,
        Message::Assistant {
            content,
            reasoning,
            tool_calls,
        } => {
            let mut n = content.as_ref().map_or(0, std::string::String::len);
            n += reasoning.as_ref().map_or(0, std::string::String::len);
            n += tool_calls
                .iter()
                .map(|c| c.arguments.to_string().len())
                .sum::<usize>();
            n as u64
        }
        Message::Tool { content, .. } => content.len() as u64,
    }
}

/// The nearest ancestor of `cwd` containing a `.git` directory, or `cwd`
/// itself when there is none (PLAN 6.3).
fn find_git_root(cwd: &Path) -> PathBuf {
    let mut path = cwd.to_path_buf();
    loop {
        if path.join(".git").is_dir() {
            return path;
        }
        match path.parent() {
            Some(parent) => path = parent.to_path_buf(),
            None => return cwd.to_path_buf(),
        }
    }
}
