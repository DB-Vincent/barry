//! The `barry` binary: entry point, headless mode and the REPL.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use barry_sandbox::run_helper_if_invoked;
use clap::Parser;
use futures::channel::mpsc;
use futures::stream::StreamExt;
use tokio_util::sync::CancellationToken;
use url::Url;

use barry_core::approval_file::PolicyFileApprover;
use barry_core::config::Config;
use barry_core::session::{self, SessionLog};
use barry_core::{Agent, Approver, BoxFuture, RunStats};
use barry_llm::{Compat, OpenAiProvider, Provider};
use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, Event, RunSummary, StopReason};

/// Default endpoint until PLAN 6.8 (named model profiles) lands in M6.
const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";

mod exit;
mod render;
mod repl;
mod subscription;

/// Read `BARRY_BASE_URL`, falling back to the local default.
pub(crate) fn parse_base_url() -> Result<Url, String> {
    let raw_base_url =
        std::env::var("BARRY_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    Url::parse(&raw_base_url)
        .map_err(|err| format!("config error: invalid BARRY_BASE_URL {raw_base_url:?}: {err}"))
}

/// Build the provider used by both headless mode and the REPL.
pub(crate) fn build_provider(model: String, base_url: &Url) -> Arc<dyn Provider> {
    Arc::new(OpenAiProvider::new(
        model,
        base_url.clone(),
        None,
        8192,
        Compat {
            reasoning_field: Some("reasoning_content".into()),
            ..Compat::default()
        },
    ))
}

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
    /// Resume a session from a log file or a UUID/timestamp prefix
    #[arg(long = "resume")]
    resume: Option<String>,
    /// Approve only the actions listed in this TOML file (headless only);
    /// every other action that needs approval is denied
    #[arg(long = "approval-file", requires = "prompt")]
    approval_file: Option<PathBuf>,
    /// Stop a run after this many input plus output tokens
    #[arg(long = "max-tokens")]
    max_tokens: Option<u64>,
    /// Stop a run after this estimated cost in USD (needs token prices in config)
    #[arg(long = "max-cost-usd")]
    max_cost_usd: Option<f64>,
    /// Stop a run after this many wall-clock seconds
    #[arg(long = "max-wall-secs")]
    max_wall_secs: Option<u64>,
    /// Stop a run after this many cumulative seconds of bash commands
    #[arg(long = "max-bash-secs")]
    max_bash_secs: Option<u64>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Launch a native CLI using its own subscription and security controls
    #[command(long_about = subscription::HELP)]
    Subscription {
        #[command(subcommand)]
        command: subscription::Backend,
    },
    /// Check the policy decision for a command
    Rules {
        #[command(subcommand)]
        command: Option<RulesCommands>,
    },
    /// Inspect session logs
    Log {
        #[command(subcommand)]
        command: LogCommands,
    },
    /// Show the configuration in effect
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
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

#[derive(clap::Subcommand, Debug)]
enum ConfigCommands {
    /// Print the effective config and the file it came from
    Show,
}

#[derive(clap::Subcommand, Debug)]
enum LogCommands {
    /// Verify the hash chain of a session log
    Verify {
        /// Path to the session log file
        file: PathBuf,
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
    // If re-executed as the sandbox helper (Linux bwrap target), install the
    // seccomp filter and run the requested command, never returning.
    run_helper_if_invoked();

    // A native CLI launch does not use Barry's configuration or agent.
    let args: Vec<_> = std::env::args_os().collect();
    let subscription_requested = args
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != "--")
        .any(|arg| arg == "subscription");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            if err.use_stderr() && subscription_requested {
                eprintln!(
                    "Native CLI arguments go after --: barry subscription <codex|claude> -- [arguments]"
                );
            }
            return ExitCode::from(code as u8);
        }
    };
    if let Some(Commands::Subscription { command }) = &cli.command {
        if cli.prompt.is_some()
            || cli.json
            || cli.model.is_some()
            || cli.resume.is_some()
            || cli.approval_file.is_some()
            || cli.max_tokens.is_some()
            || cli.max_cost_usd.is_some()
            || cli.max_wall_secs.is_some()
            || cli.max_bash_secs.is_some()
        {
            eprintln!(
                "error: Barry run flags cannot be used with subscription; native CLI arguments go after --"
            );
            return ExitCode::from(exit::CONFIG);
        }
        return command.launch();
    }

    // Native Barry modes load config; on error, exit 2 with a clean message.
    let mut cfg = match Config::load() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => Config::default(),
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(exit::CONFIG);
        }
    };

    // Flags override the `[budgets]` config section.
    let budgets = &mut cfg.budgets;
    budgets.max_total_tokens = cli.max_tokens.or(budgets.max_total_tokens);
    budgets.max_cost_usd = cli.max_cost_usd.or(budgets.max_cost_usd);
    budgets.max_wall_secs = cli.max_wall_secs.or(budgets.max_wall_secs);
    budgets.max_bash_secs = cli.max_bash_secs.or(budgets.max_bash_secs);
    if let Err(message) = budgets.validate() {
        eprintln!("config error: {message}");
        return ExitCode::from(2);
    }

    if let Some(command) = cli.command {
        return run_command(command, &cfg);
    }

    let Some(prompt) = cli.prompt else {
        return repl::run(cfg, cli.model, cli.resume).await;
    };

    run_headless(
        cfg,
        prompt,
        cli.json,
        cli.model,
        cli.resume,
        cli.approval_file,
    )
    .await
}

fn run_command(command: Commands, cfg: &Config) -> ExitCode {
    match command {
        // Routed before configuration loading in main.
        Commands::Subscription { command } => command.launch(),
        Commands::Log { command } => match command {
            LogCommands::Verify { file } => match session::verify(&file) {
                Ok(report) => match report.broken_at {
                    None => {
                        println!("ok ({} entries)", report.entries);
                        ExitCode::SUCCESS
                    }
                    Some(line) => {
                        println!("broken at line {line}");
                        ExitCode::from(1)
                    }
                },
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            },
        },
        Commands::Rules { command } => match command {
            Some(RulesCommands::Check { command }) => {
                let policy_cfg = barry_policy::PolicyConfig {
                    cwd: std::env::current_dir().unwrap_or_default(),
                    home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
                    extra_writable: vec![],
                    read_deny: cfg.fs_read_deny.clone(),
                    protected: cfg.fs_protected.clone(),
                    rules: cfg.rules.clone(),
                    network: cfg.sandbox_network,
                };
                let policy = match barry_policy::Policy::new(policy_cfg) {
                    Ok(policy) => policy,
                    // A policy that cannot be built is a config error, not a
                    // reason to panic inside `rules check` (#44).
                    Err(err) => {
                        eprintln!("error: {err}");
                        return ExitCode::from(2);
                    }
                };
                let (decision, rule_id) =
                    policy.check_bash(&command, &barry_policy::SessionGrants::new());
                match decision {
                    barry_protocol::Decision::Allow => {
                        if let Some(id) = &rule_id {
                            println!("allow (rule: {id})");
                        } else {
                            println!("allow");
                        }
                        ExitCode::SUCCESS
                    }
                    barry_protocol::Decision::Deny { reason } => {
                        if let Some(id) = &rule_id {
                            eprintln!("deny: {reason} (rule: {id})");
                        } else {
                            eprintln!("deny: {reason}");
                        }
                        ExitCode::from(1)
                    }
                    barry_protocol::Decision::Ask { reason } => {
                        if let Some(id) = &rule_id {
                            eprintln!("ask: {reason} (rule: {id})");
                        } else {
                            eprintln!("ask: {reason}");
                        }
                        ExitCode::from(1)
                    }
                    // Decision is non-exhaustive: treat an unknown one as a refusal.
                    _ => {
                        eprintln!("deny: unknown policy decision");
                        ExitCode::from(1)
                    }
                }
            }
            None => {
                eprintln!("error: `rules` requires a subcommand");
                ExitCode::from(exit::CONFIG)
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Show => show_config(cfg),
        },
    }
}

/// `barry config show`: print the configuration in effect and the file it came
/// from (#27).
///
/// Values are the merged result, so the built-in defaults are visible even when
/// no file exists - which is the whole point when a user wonders why a read was
/// denied or a network command refused.
fn show_config(cfg: &Config) -> ExitCode {
    let configured = std::env::var("BARRY_CONFIG")
        .ok()
        .map(PathBuf::from)
        .or_else(barry_core::config::default_config_path);

    match configured.as_ref() {
        Some(path) if path.exists() => println!("config_file: {}", path.display()),
        Some(path) => println!(
            "config_file: none, built-in defaults applied (looked at {})",
            path.display()
        ),
        None => println!("config_file: none, built-in defaults applied"),
    }

    println!("default_model: {}", cfg.default_model);
    println!("max_turns: {}", cfg.max_turns);
    println!("context_window: {}", cfg.context_window);
    println!("sandbox.network: {}", cfg.sandbox_network);
    println!("redaction.tool_output: {}", cfg.redact_tool_output);
    println!("fs.read_deny: {}", list_or_none(&cfg.fs_read_deny));
    println!("fs.protected: {}", list_or_none(&cfg.fs_protected));

    if cfg.rules.is_empty() {
        println!("rules: none");
    }
    for rule in &cfg.rules {
        println!(
            "rule: {} {:?} -> {}",
            rule.id,
            rule.r#match,
            decision_name(&rule.decision)
        );
    }

    if cfg.hooks.is_empty() {
        println!("hooks: none");
    }
    for hook in &cfg.hooks {
        println!(
            "hook: {} -> {} (timeout {}s, fail_closed {})",
            hook.matcher,
            hook.command.join(" "),
            hook.timeout_secs,
            hook.fail_closed
        );
    }

    ExitCode::SUCCESS
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn decision_name(decision: &barry_protocol::Decision) -> &'static str {
    match decision {
        barry_protocol::Decision::Allow => "allow",
        barry_protocol::Decision::Deny { .. } => "deny",
        barry_protocol::Decision::Ask { .. } => "ask",
        // Decision is non-exhaustive: label a variant this code does not know.
        _ => "unknown",
    }
}

async fn run_headless(
    mut cfg: Config,
    prompt: String,
    json: bool,
    model: Option<String>,
    resume: Option<String>,
    approval_file: Option<PathBuf>,
) -> ExitCode {
    // Without an approval file every request is denied. With one, only the
    // listed actions are approved and the rest are still denied.
    let approver: Arc<dyn Approver> = match approval_file {
        None => Arc::new(HeadlessApprover),
        Some(path) => {
            let cwd = std::env::current_dir().unwrap_or_default();
            match PolicyFileApprover::from_file(&path, &cwd, cfg.fs_protected.clone()) {
                Ok(approver) => Arc::new(approver),
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let model = model.unwrap_or_else(|| cfg.default_model.clone());
    // The audit log records the model actually used, including --model.
    cfg.default_model = model.clone();

    // Temporary provider wiring until PLAN 6.8 model profiles (M6): the base
    // URL comes from the environment, with a local-server default.
    let base_url = match parse_base_url() {
        Ok(url) => url,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(exit::CONFIG);
        }
    };

    let provider = build_provider(model, &base_url);

    // Build the sandbox policy from config. Headless mode never trusts
    // project config, so only defaults + config file values apply.
    // A policy that cannot be built is a config error: report it and exit 2
    // rather than panicking halfway through starting a session (#44).
    let policy = match Policy::new(barry_policy::PolicyConfig {
        cwd: std::env::current_dir().unwrap_or_default(),
        home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
        extra_writable: vec![],
        read_deny: cfg.fs_read_deny.clone(),
        protected: cfg.fs_protected.clone(),
        rules: cfg.rules.clone(),
        network: cfg.sandbox_network,
    }) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    let mut agent = match resume {
        Some(spec) => {
            let path = match session::resolve_session(&spec) {
                Ok(path) => path,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(exit::CONFIG);
                }
            };
            match Agent::resume(cfg, provider, approver, policy, &path) {
                Ok(agent) => agent,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            }
        }
        None => {
            let mut agent = match Agent::new(cfg, provider, approver, policy) {
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

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(async move {
        let result = agent.run_turn(&prompt, tx, cancel).await;
        (agent, result)
    });

    let mut turn_limited = false;
    let mut wrote_text = false;
    let mut thinking = render::Thinking::default();
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
            thinking.finish();
            print!("{text}");
            let _ = std::io::stdout().flush();
            wrote_text = true;
        } else if let Event::ReasoningDelta(text) = &event {
            thinking.delta(text);
        }
    }

    thinking.finish();
    if wrote_text {
        println!();
    }

    let (stats, outcome) = match handle.await {
        Ok((agent, result)) => (
            agent.run_stats().clone(),
            result.map_err(|err| err.to_string()),
        ),
        Err(err) => (
            RunStats::default(),
            Err(format!("agent task failed: {err}")),
        ),
    };
    let stop = match outcome {
        Ok(stop) => stop,
        Err(message) => {
            eprintln!("{message}");
            StopReason::Error(message)
        }
    };

    // PLAN 6.9 exit codes, extended in `exit`.
    let code = exit::for_run(&stop, turn_limited, stats.denied_actions);

    if json {
        // The last line of `--json` output: what a CI job or orchestrator
        // needs without replaying every event.
        let summary = Event::RunSummary(RunSummary {
            stop_reason: stop,
            exit_code: code,
            turn_limit_reached: turn_limited,
            denied_actions: stats.denied_actions,
            usage: stats.usage,
            files_changed: stats.files_changed.into_iter().collect(),
        });
        match serde_json::to_string(&summary) {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("failed to serialize summary: {err}");
                return ExitCode::from(exit::FAILURE);
            }
        }
    }

    ExitCode::from(code)
}
