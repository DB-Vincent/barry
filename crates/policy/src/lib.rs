//! Policy engine for barry.

use barry_protocol::Decision;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {}

#[derive(Debug, Clone)]
pub struct Policy;

impl Policy {
    pub fn new() -> Result<Self, PolicyError> {
        Ok(Self)
    }

    pub fn check_bash(&self, command: &str) -> Decision {
        // Default deny rules
        let deny_rules = [
            "sudo",
            "su",
            "doas",
            "rm -rf /",
            "rm -rf ~",
            "rm -rf /*",
            "chmod -R 777",
            "chown -R",
        ];
        for &rule in &deny_rules {
            if command.contains(rule) {
                return Decision::Deny {
                    reason: format!("command matches deny rule: {rule}"),
                };
            }
        }

        // Default allow rules
        let allow_prefixes = [
            "ls",
            "cat",
            "head",
            "tail",
            "wc",
            "pwd",
            "echo",
            "which",
            "file",
            "stat",
            "tree",
            "rg",
            "fd",
            "grep",
            "find",
            "sort",
            "uniq",
            "cut",
            "diff",
            "git status",
            "git diff",
            "git log",
            "git show",
            "git branch",
            "git rev-parse",
            "git blame",
            "cargo check",
            "cargo build",
            "cargo test",
            "cargo fmt",
            "cargo clippy",
            "cargo tree",
        ];
        for &prefix in &allow_prefixes {
            if command.starts_with(prefix) {
                return Decision::Allow;
            }
        }

        Decision::Ask {
            reason: "no matching rule".to_string(),
        }
    }
}
