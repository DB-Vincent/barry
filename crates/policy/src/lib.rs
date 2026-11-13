//! Policy engine for barry.
//!
//! Two layers: path-based decisions for file reads/writes, and rule-based
//! decisions for bash commands. Path canonicalisation rejects `..` and
//! resolves symlinks (PLAN 6.1.1, BC-3.5).

mod path;

use std::path::{Path, PathBuf};
use thiserror::Error;

pub use barry_protocol::Decision;
pub use path::{canonicalise, is_under, PathError};

/// Errors from the policy engine.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid path: {0:?}")]
    InvalidPath(PathBuf),
}

/// Configuration for the policy engine (PLAN 6.1).
pub struct PolicyConfig {
    pub cwd: PathBuf,
    pub home: PathBuf,
    pub extra_writable: Vec<PathBuf>,
    pub read_deny: Vec<String>,
    pub protected: Vec<String>,
    pub rules: Vec<BashRule>,
}

/// A bash rule: a `match` string against a command, with a decision.
#[derive(Debug, Clone)]
pub struct BashRule {
    pub id: String,
    pub r#match: String,
    pub decision: Decision,
}

/// The writable roots for a session: cwd, extra writable dirs, and grants.
#[derive(Debug, Clone)]
pub struct Policy {
    cwd: PathBuf,
    read_deny: Vec<PathBuf>,
    protected: Vec<String>,
    writable_roots: Vec<PathBuf>,
    grants: Vec<PathBuf>,
    rules: Vec<BashRule>,
}

impl Policy {
    pub fn new(cfg: PolicyConfig) -> Result<Self, PolicyError> {
        let read_deny = cfg
            .read_deny
            .iter()
            .map(|entry| canonicalise_read_deny(&cfg.home, entry))
            .collect();

        let mut writable_roots = vec![cfg.cwd.clone()];
        writable_roots.extend(cfg.extra_writable.iter().cloned());

        Ok(Self {
            cwd: cfg.cwd,
            read_deny,
            protected: cfg.protected,
            writable_roots,
            grants: Vec::new(),
            rules: cfg.rules,
        })
    }

    /// Check a read against policy. Reads under a read-deny entry are denied;
    /// everything else is allowed.
    pub fn check_read(&self, path: &Path) -> Decision {
        let canonical = match canonicalise(&self.cwd, path) {
            Ok(c) => c,
            Err(_) => {
                return Decision::Deny {
                    reason: "cannot canonicalise path".into(),
                }
            }
        };

        for deny in &self.read_deny {
            if is_under(&canonical, deny) {
                return Decision::Deny {
                    reason: "path is read-denied".into(),
                };
            }
        }

        Decision::Allow
    }

    /// Check a write against policy.
    ///
    /// Returns `(Decision, Option<PathBuf>)`. The grant path, when `Some`,
    /// is the parent directory the user would need to grant.
    pub fn check_write(&self, path: &Path) -> (Decision, Option<PathBuf>) {
        let canonical = match canonicalise(&self.cwd, path) {
            Ok(c) => c,
            Err(_) => {
                return (
                    Decision::Ask {
                        reason: "cannot canonicalise path".into(),
                    },
                    None,
                )
            }
        };

        // Protected path components (e.g. `.git`, `.env`) always ask.
        if let Some(name) = canonical.file_name().and_then(|n| n.to_str()) {
            if self.protected.iter().any(|p| p == name) {
                return (
                    Decision::Ask {
                        reason: format!("protected path: {name}"),
                    },
                    None,
                );
            }
        }

        // Inside a writable root: allow, no grant needed.
        for root in &self.writable_roots {
            if is_under(&canonical, root) {
                return (Decision::Allow, None);
            }
        }

        // Outside all writable roots: ask, with grant offered for the parent dir.
        let parent = canonical.parent().unwrap_or(Path::new("")).to_path_buf();
        (
            Decision::Ask {
                reason: "path is outside the working directory".into(),
            },
            Some(parent),
        )
    }

    /// Record a directory grant, making it writable for the rest of the session.
    pub fn grant_dir(&mut self, dir: &Path) -> Result<(), PolicyError> {
        let canonical = match canonicalise(&self.cwd, dir) {
            Ok(c) => c,
            Err(_) => return Err(PolicyError::InvalidPath(dir.to_path_buf())),
        };
        self.grants.push(canonical.clone());
        self.writable_roots.push(canonical);
        Ok(())
    }

    /// Check a bash command against the rule table. Deny > ask > allow.
    pub fn check_bash(&self, command: &str) -> Decision {
        // Default deny rules (substring match)
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

        // Configured rules (exact match on `match` field)
        for rule in &self.rules {
            if command == rule.r#match {
                return rule.decision.clone();
            }
        }

        // Default allow rules (prefix match)
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
            reason: "no matching rule".into(),
        }
    }
}

/// Expand `~` to `$HOME` in a path string.
fn expand_tilde(home: &Path, p: &str) -> PathBuf {
    let p = p.trim();
    if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else if p == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(p)
    }
}

/// Canonicalise a read-deny entry: expand `~`, then canonicalise if it exists.
fn canonicalise_read_deny(home: &Path, entry: &str) -> PathBuf {
    let path = expand_tilde(home, entry);
    if path.exists() {
        std::fs::canonicalize(&path).unwrap_or(path)
    } else {
        path
    }
}
