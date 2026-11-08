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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Rules { command }) => match command {
            Some(RulesCommands::Check { command }) => {
                let policy = barry_policy::Policy::new().expect("policy");
                match policy.check_bash(&command) {
                    barry_protocol::Decision::Allow => println!("allow"),
                    barry_protocol::Decision::Deny { reason } => {
                        eprintln!("deny: {reason}");
                        std::process::exit(1);
                    }
                    barry_protocol::Decision::Ask { reason } => {
                        eprintln!("ask: {reason}");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!("error: `rules` requires a subcommand");
                std::process::exit(2);
            }
        },
        None => {
            // --version handled by clap automatically
        }
    }
}
