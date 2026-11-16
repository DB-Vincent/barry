//! Launch installed native subscription clients without entering Barry's agent.

use std::ffi::OsString;
use std::process::ExitCode;

pub(crate) const HELP: &str = "Launch an installed Codex or Claude CLI using its own subscription login. The selected CLI owns tools and approvals. Barry's policy, sandbox, audit and budgets do not govern this mode. Native arguments must go after --; omit arguments to launch interactively. Barry does not install clients or change their login/configuration.";

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Backend {
    /// Launch the installed Codex CLI (sign in with `ChatGPT` using `codex login`)
    #[command(after_help = HELP)]
    Codex(NativeArgs),
    /// Launch the installed Claude CLI using its own subscription login
    #[command(after_help = HELP)]
    Claude(NativeArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct NativeArgs {
    /// Arguments passed unchanged to the native CLI, after --
    #[arg(last = true)]
    args: Vec<OsString>,
}

impl Backend {
    pub(crate) fn launch(&self) -> ExitCode {
        let (program, args) = match self {
            Self::Codex(args) => ("codex", args),
            Self::Claude(args) => ("claude", args),
        };
        launch(program, &args.args)
    }
}

#[cfg(unix)]
fn launch(program: &str, args: &[OsString]) -> ExitCode {
    use std::os::unix::process::CommandExt;

    // exec preserves cwd, environment, stdio, terminal signals and exit status.
    // Never use a shell: every native argument remains a single OS string.
    let error = std::process::Command::new(program).args(args).exec();
    if error.kind() == std::io::ErrorKind::NotFound {
        eprintln!(
            "error: {program} CLI not found. Install the official {program} CLI and ensure it is on PATH."
        );
        ExitCode::from(127)
    } else {
        // Do not print arguments, environment or arbitrary native output.
        eprintln!(
            "error: could not execute {program} CLI ({:?})",
            error.kind()
        );
        ExitCode::from(126)
    }
}

#[cfg(not(unix))]
fn launch(_program: &str, _args: &[OsString]) -> ExitCode {
    eprintln!("error: native subscription launch requires macOS or Linux");
    ExitCode::from(126)
}
