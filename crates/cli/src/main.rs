use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "barry",
    version = env!("CARGO_PKG_VERSION"),
    about = "A security-first coding agent harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Check the policy decision for a command
    RulesCheck {
        /// The command to check
        command: String,
    },
}

fn main() {
    let _cli = Cli::parse();
}
