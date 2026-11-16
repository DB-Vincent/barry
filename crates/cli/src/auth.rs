//! Delegate authentication to official native CLIs without handling tokens.

use std::process::{ExitStatus, Stdio};

use clap::Parser;

pub(crate) const REPL_USAGE: &str = "usage: /auth login anthropic [--profile <name>] [--no-browser] | /auth status anthropic [--profile <name>] | /auth logout anthropic [--profile <name>] | /auth login codex [--no-browser] | /auth status codex | /auth logout codex";

#[derive(clap::ValueEnum, Clone, Debug)]
pub(crate) enum Provider {
    Anthropic,
    Codex,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Account {
    #[arg(value_enum)]
    provider: Provider,
    #[command(flatten)]
    profile: Profile,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Profile {
    /// Anthropic account profile (defaults to barry); unsupported for Codex
    #[arg(long = "profile", value_parser = parse_profile)]
    name: Option<String>,
}

fn parse_profile(name: &str) -> Result<String, String> {
    if !(1..=64).contains(&name.len())
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("profile must contain 1 to 64 ASCII letters, digits, dots, underscores or hyphens and start with a letter or digit".into());
    }
    Ok(name.to_string())
}

#[derive(clap::Args, Debug)]
pub(crate) struct Login {
    #[arg(value_enum)]
    provider: Provider,
    #[command(flatten)]
    profile: Profile,
    /// Anthropic: print login URL; Codex: use native device authentication
    #[arg(long)]
    no_browser: bool,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Sign in through the selected official CLI
    Login(Login),
    /// Show native authentication configuration (does not validate credentials)
    Status(Account),
    /// Sign out the selected Anthropic profile or native Codex account
    Logout(Account),
}

#[derive(Parser)]
struct ReplCommand {
    #[command(subcommand)]
    command: Command,
}

impl Command {
    /// The REPL accepts exactly the same arguments as the standalone command.
    pub(crate) fn parse_repl(input: &str) -> Option<Self> {
        ReplCommand::try_parse_from(std::iter::once("auth").chain(input.split_whitespace()))
            .ok()
            .map(|parsed| parsed.command)
    }

    pub(crate) async fn run(&self) -> u8 {
        let (action, no_browser, provider, profile) = match self {
            Self::Login(login) => (
                "login",
                login.no_browser,
                &login.provider,
                &login.profile.name,
            ),
            Self::Status(account) => ("status", false, &account.provider, &account.profile.name),
            Self::Logout(account) => ("logout", false, &account.provider, &account.profile.name),
        };
        let program = match provider {
            Provider::Anthropic => "ant",
            Provider::Codex => "codex",
        };
        let mut command = tokio::process::Command::new(program);
        match provider {
            Provider::Anthropic => {
                command
                    .args([
                        "auth",
                        action,
                        "--profile",
                        profile.as_deref().unwrap_or("barry"),
                    ])
                    .env_remove("ANTHROPIC_API_KEY")
                    .env_remove("ANTHROPIC_AUTH_TOKEN")
                    .env_remove("ANTHROPIC_PROFILE");
                if no_browser {
                    command.arg("--no-browser");
                }
            }
            Provider::Codex => {
                if profile.is_some() {
                    eprintln!(
                        "error: --profile is only supported for Anthropic authentication; Codex uses its native account credentials"
                    );
                    return 2;
                }
                match action {
                    "status" => {
                        command.args(["login", "status"]);
                    }
                    _ => {
                        command.arg(action);
                    }
                }
                if no_browser {
                    command.arg("--device-auth");
                }
                command
                    .env_remove("OPENAI_API_KEY")
                    .env_remove("CODEX_ACCESS_TOKEN");
            }
        }
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);

        // Register before spawning so Ctrl-C cannot terminate Barry between
        // launching the CLI and installing the handler. The REPL resumes afterward.
        #[cfg(unix)]
        let Ok(mut interrupt) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        else {
            eprintln!("error: could not install authentication interrupt handler");
            return 126;
        };
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match provider {
                    Provider::Anthropic => eprintln!(
                        "error: official ant CLI not found. Install it with `brew install anthropics/tap/ant` and ensure ant is on PATH."
                    ),
                    Provider::Codex => eprintln!(
                        "error: official Codex CLI not found. Install it using https://developers.openai.com/codex/cli and ensure codex is on PATH."
                    ),
                }
                return 127;
            }
            Err(error) => {
                eprintln!("error: could not launch {program} CLI ({:?})", error.kind());
                return 126;
            }
        };

        #[cfg(unix)]
        let status = tokio::select! {
            status = child.wait() => status,
            _ = interrupt.recv() => {
                // Terminal Ctrl-C reaches the child too. Allow native terminal and
                // callback cleanup before falling back to kill and reap.
                if tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await.is_err() {
                    let _ = child.kill().await;
                }
                return 130;
            }
        };
        #[cfg(not(unix))]
        let status = child.wait().await;

        match status {
            Ok(status) => exit_code(status),
            Err(_) => {
                eprintln!("error: could not wait for {program} CLI");
                126
            }
        }
    }
}

fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return code as u8;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return (128 + signal) as u8;
        }
    }
    126
}
