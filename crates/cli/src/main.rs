//! The `barry` binary: entry point, headless mode and (later) the REPL.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use futures::channel::mpsc;
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;
use url::Url;

use barry_core::config::Config;
use barry_core::{Agent, Approver, BoxFuture};
use barry_llm::{Compat, OpenAiProvider};
use barry_protocol::{ApprovalChoice, ApprovalRequest, Event, StopReason};

/// Default endpoint until PLAN 6.8 (named model profiles) lands in M6.
const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";

#[derive(Parser, Debug)]
#[command(
    name = "barry",
    version = env!("CARGO_PKG_VERSION"),
    about = "A security-first coding agent harness"
)]
struct Cli {
    /// Run one prompt headless and print the answer, instead of the REPL
    #[arg(short = 'p', long = "prompt")]
    prompt: Option<String>,
    /// Write each event as one JSON object per line (headless only)
    #[arg(long = "json", requires = "prompt")]
    json: bool,
    /// Model id sent to the provider
    #[arg(long = "model")]
    model: Option<String>,
    /// Allow bash to run without a sandbox. M2 only; removed in M4.
    #[arg(long = "dev-unsafe-bash", hide = true)]
    dev_unsafe_bash: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Check the policy decision for a command
    Rules {
        #[command(subcommand)]
        command: Option<RulesCommands>,
    },
}

#[derive(clap::Subcommand, Debug)]
enum RulesCommands {
    /// Check a command against policy rules
    Check {
        /// The command to check
        command: String,
    },
}

/// PLAN 6.9: headless mode never trusts the user with a prompt. Every request
/// is denied; M3 turns that into "requires user approval, which is unavailable
/// in headless mode" for the model (BC-3.10).
struct HeadlessApprover;

impl Approver for HeadlessApprover {
    fn decide(&self, _req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        Box::pin(async { ApprovalChoice::Deny })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // Load config first; on error, exit 2 with a clean message.
    let mut cfg = match Config::load() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => Config::default(),
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };

    let cli = Cli::parse();

    if let Some(command) = cli.command {
        return run_command(command);
    }

    let Some(prompt) = cli.prompt else {
        eprintln!("error: interactive mode is not available yet; use -p \"<prompt>\"");
        return ExitCode::from(2);
    };

    // A file on disk must not be able to turn off a safety property, so this
    // flag is only ever applied from the command line (see Config).
    cfg.dev_unsafe_bash = cli.dev_unsafe_bash;

    run_headless(cfg, prompt, cli.json, cli.model).await
}

fn run_command(command: Commands) -> ExitCode {
    match command {
        Commands::Rules { command } => match command {
            Some(RulesCommands::Check { command }) => {
                let cfg = barry_policy::PolicyConfig {
                    cwd: std::env::current_dir().unwrap_or_default(),
                    home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
                    extra_writable: vec![],
                    read_deny: vec![],
                    protected: vec![],
                    rules: vec![],
                };
                let policy = barry_policy::Policy::new(cfg).expect("policy");
                match policy.check_bash(&command) {
                    barry_protocol::Decision::Allow => {
                        println!("allow");
                        ExitCode::SUCCESS
                    }
                    barry_protocol::Decision::Deny { reason } => {
                        eprintln!("deny: {reason}");
                        ExitCode::from(1)
                    }
                    barry_protocol::Decision::Ask { reason } => {
                        eprintln!("ask: {reason}");
                        ExitCode::from(1)
                    }
                }
            }
            None => {
                eprintln!("error: `rules` requires a subcommand");
                ExitCode::from(2)
            }
        },
    }
}

async fn run_headless(cfg: Config, prompt: String, json: bool, model: Option<String>) -> ExitCode {
    let model = model.unwrap_or_else(|| cfg.default_model.clone());

    // Temporary provider wiring until PLAN 6.8 model profiles (M6): the base
    // URL comes from the environment, with a local-server default.
    let raw_base_url =
        std::env::var("BARRY_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let base_url = match Url::parse(&raw_base_url) {
        Ok(url) => url,
        Err(err) => {
            eprintln!("config error: invalid BARRY_BASE_URL {raw_base_url:?}: {err}");
            return ExitCode::from(2);
        }
    };

    let provider = Arc::new(OpenAiProvider::new(
        model,
        base_url,
        None,
        8192,
        Compat {
            reasoning_field: Some("reasoning_content".into()),
            ..Compat::default()
        },
    ));
    let mut agent = match Agent::new(cfg, provider, Arc::new(HeadlessApprover), None) {
        Ok(agent) => agent,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(async move { agent.run_turn(&prompt, tx, cancel).await });

    let mut turn_limited = false;
    let mut wrote_text = false;
    while let Some(event) = rx.next().await {
        if matches!(&event, Event::Notice(msg) if msg == "turn limit reached") {
            turn_limited = true;
        }

        if json {
            match serde_json::to_string(&event) {
                Ok(line) => println!("{line}"),
                Err(err) => {
                    eprintln!("failed to serialize event: {err}");
                    return ExitCode::from(1);
                }
            }
        } else if let Event::TextDelta(text) = &event {
            print!("{text}");
            let _ = std::io::stdout().flush();
            wrote_text = true;
        } else if let Event::ReasoningDelta(text) = &event {
            eprint!("thinking: {text}");
            let _ = std::io::stderr().flush();
        }
    }

    if wrote_text {
        println!();
    }

    let stop = match handle.await {
        Ok(Ok(stop)) => stop,
        Ok(Err(err)) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
        Err(err) => {
            eprintln!("agent task failed: {err}");
            return ExitCode::from(1);
        }
    };

    // PLAN 6.9 exit codes.
    match stop {
        StopReason::Stop if turn_limited => ExitCode::from(3),
        StopReason::Stop => ExitCode::SUCCESS,
        StopReason::Aborted | StopReason::Error(_) => ExitCode::from(1),
        StopReason::Length | StopReason::ToolCalls | StopReason::ContentFilter => ExitCode::from(1),
    }
}
