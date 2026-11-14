//! The interactive REPL (PLAN 6.9): a minimal line interface in cwd.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use barry_core::config::Config;
use barry_core::session::{self, SessionLog};
use barry_core::{Agent, Approver, BoxFuture};
use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, Event, StopReason};
use futures::channel::mpsc;
use futures::stream::StreamExt;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::render::Thinking;
use crate::{build_provider, parse_base_url};

/// Answers approvals from the terminal, or from the piped stdin used by
/// acceptance tests (PLAN 6.9: "answers are read from the same input stream").
struct ReplApprover {
    /// The token for the turn in progress, so Ctrl-C can abandon a prompt.
    cancel: Mutex<CancellationToken>,
    /// The same buffered stdin the REPL loop reads, so an answer typed ahead
    /// is not lost between two buffers.
    input: Arc<tokio::sync::Mutex<BufReader<Stdin>>>,
}

impl ReplApprover {
    fn new(input: Arc<tokio::sync::Mutex<BufReader<Stdin>>>) -> Self {
        Self {
            cancel: Mutex::new(CancellationToken::new()),
            input,
        }
    }

    fn set_cancel(&self, cancel: &CancellationToken) {
        *self.cancel.lock().expect("approval lock") = cancel.clone();
    }
}

impl Approver for ReplApprover {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        let cancel = self.cancel.lock().expect("approval lock").clone();
        let input = self.input.clone();
        let summary = req.summary.clone();
        Box::pin(async move {
            // Start the prompt on its own line, after any streamed text.
            println!();
            println!("Allow {summary}? [o]nce / [a]lways this session / [d]eny:");
            let _ = std::io::stdout().flush();

            let mut line = String::new();
            tokio::select! {
                _ = cancel.cancelled() => ApprovalChoice::Deny,
                read = async {
                    let mut input = input.lock().await;
                    input.read_line(&mut line).await
                } => {
                    match read {
                        Ok(_) => match line.trim().to_ascii_lowercase().as_str() {
                            "o" | "once" => ApprovalChoice::Once,
                            "a" | "always" | "always this session" => {
                                ApprovalChoice::AlwaysThisSession
                            }
                            // Anything else, including an empty line or EOF, denies.
                            _ => ApprovalChoice::Deny,
                        },
                        Err(_) => ApprovalChoice::Deny,
                    }
                }
            }
        })
    }
}

/// Renders agent events in the line-oriented style of PLAN 6.9.
#[derive(Default)]
struct Renderer {
    wrote_text: bool,
    thinking: Thinking,
}

impl Renderer {
    fn event(&mut self, event: &Event) {
        match event {
            Event::TextDelta(text) => {
                self.thinking.finish();
                print!("{text}");
                let _ = std::io::stdout().flush();
                self.wrote_text = true;
            }
            Event::ReasoningDelta(text) => self.thinking.delta(text),
            Event::ToolStarted { name, display, .. } => {
                self.thinking.finish();
                self.newline();
                println!("● {name}: {}", tool_detail(name, display));
            }
            Event::ToolFinished { ok, display, .. } => {
                self.thinking.finish();
                self.newline();
                let mark = if *ok { "✓" } else { "✗" };
                println!("  {mark} {display}");
            }
            Event::Notice(text) => {
                self.thinking.finish();
                self.newline();
                println!("{text}");
            }
            // The approver prints its own prompt.
            Event::ApprovalNeeded(_) => {}
            Event::TurnStarted | Event::TurnFinished { .. } => {}
        }
    }

    fn newline(&mut self) {
        if self.wrote_text {
            println!();
            self.wrote_text = false;
        }
    }

    fn finish(&mut self) {
        self.thinking.finish();
        self.newline();
    }
}

/// Turn `bash {"command":"cargo test"}` into `cargo test`.
fn tool_detail(name: &str, display: &str) -> String {
    let detail = display
        .strip_prefix(name)
        .map(str::trim_start)
        .unwrap_or(display);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(detail) {
        let key = match name {
            "bash" => "command",
            "read" | "write" | "edit" => "path",
            _ => "",
        };
        if let Some(text) = value.get(key).and_then(|value| value.as_str()) {
            return text.to_string();
        }
    }
    detail.to_string()
}

pub(crate) async fn run(
    mut cfg: Config,
    model: Option<String>,
    resume: Option<String>,
) -> ExitCode {
    let mut model = model.unwrap_or_else(|| cfg.default_model.clone());
    // The audit log records the model actually used, including --model.
    cfg.default_model = model.clone();

    let base_url = match parse_base_url() {
        Ok(url) => url,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };

    let policy = Policy::new(barry_policy::PolicyConfig {
        cwd: std::env::current_dir().unwrap_or_default(),
        home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
        extra_writable: vec![],
        read_deny: cfg.fs_read_deny.clone(),
        protected: cfg.fs_protected.clone(),
        rules: vec![],
        network: cfg.sandbox_network,
    })
    .expect("policy constructs");

    let input = Arc::new(tokio::sync::Mutex::new(BufReader::new(tokio::io::stdin())));
    let approver = Arc::new(ReplApprover::new(input.clone()));
    let provider = build_provider(model.clone(), &base_url);

    let mut agent = match resume {
        Some(spec) => {
            let path = match session::resolve_session(&spec) {
                Ok(path) => path,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(2);
                }
            };
            match Agent::resume(cfg, provider, approver.clone(), Some(policy), &path) {
                Ok(agent) => agent,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            }
        }
        None => {
            let mut agent = match Agent::new(cfg, provider, approver.clone(), Some(policy)) {
                Ok(agent) => agent,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            };
            // PLAN 6.7: every session is audited. A read-only state directory
            // must not make barry unusable, so a failure only warns.
            match SessionLog::create_default("main") {
                Ok(log) => agent = agent.with_session_log(log),
                Err(err) => eprintln!("warning: session log disabled: {err}"),
            }
            agent
        }
    };

    let interactive = std::io::stdin().is_terminal();
    // rustyline is only usable on a terminal; piped stdin (tests, scripts) is
    // read line by line instead.
    let mut editor = if interactive {
        DefaultEditor::new().ok()
    } else {
        None
    };

    let mut interrupts = 0u32;
    loop {
        let line = if let Some(editor) = editor.as_mut() {
            match editor.readline("barry> ") {
                Ok(line) => {
                    if !line.trim().is_empty() {
                        let _ = editor.add_history_entry(line.as_str());
                    }
                    line
                }
                Err(ReadlineError::Interrupted) => {
                    interrupts += 1;
                    if interrupts >= 2 {
                        break;
                    }
                    println!("(ctrl-c again to exit)");
                    continue;
                }
                Err(ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("input error: {err}");
                    break;
                }
            }
        } else {
            let mut line = String::new();
            let read = {
                let mut input = input.lock().await;
                input.read_line(&mut line).await
            };
            match read {
                Ok(0) => break,
                Ok(_) => line,
                Err(err) => {
                    eprintln!("input error: {err}");
                    break;
                }
            }
        };
        interrupts = 0;

        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        if let Some(command) = input.strip_prefix('/') {
            if !handle_command(command, &mut model, &mut agent, &base_url) {
                break;
            }
            continue;
        }

        let cancel = CancellationToken::new();
        approver.set_cancel(&cancel);
        let signal = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancel.cancel();
                }
            }
        });

        let (tx, mut rx) = mpsc::channel(64);
        let prompt = input.to_string();
        let handle = tokio::spawn(async move {
            let result = agent.run_turn(&prompt, tx, cancel).await;
            (agent, result)
        });

        let mut renderer = Renderer::default();
        while let Some(event) = rx.next().await {
            renderer.event(&event);
        }
        signal.abort();

        match handle.await {
            Ok((returned, result)) => {
                agent = returned;
                renderer.finish();
                match result {
                    Ok(StopReason::Aborted) => println!("cancelled"),
                    Ok(_) => {}
                    Err(err) => eprintln!("error: {err}"),
                }
            }
            Err(err) => {
                eprintln!("agent task failed: {err}");
                return ExitCode::from(1);
            }
        }
    }

    ExitCode::SUCCESS
}

/// Handle a slash command. Returns false when the REPL should exit.
fn handle_command(command: &str, model: &mut String, agent: &mut Agent, base_url: &Url) -> bool {
    match command {
        "exit" | "quit" => return false,
        "compact" => {
            // BC-6.7 lands with M6.
            println!("compaction is not implemented yet (M6)");
        }
        "grants" => {
            let grants = agent.grants();
            if grants.is_empty() {
                println!("no grants this session");
            } else {
                for grant in grants {
                    println!("grant: {}", grant.display());
                }
            }
        }
        "model" => println!("usage: /model <name>"),
        _ => {
            if let Some(name) = command.strip_prefix("model ") {
                let name = name.trim();
                if name.is_empty() {
                    println!("usage: /model <name>");
                } else {
                    *model = name.to_string();
                    agent.set_provider(build_provider(name.to_string(), base_url));
                    println!("model: {name}");
                }
            } else {
                println!("unknown command: /{command}");
            }
        }
    }
    true
}
