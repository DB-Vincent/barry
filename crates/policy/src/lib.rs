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
    #[error("invalid rule {id}: {reason}")]
    InvalidRule { id: String, reason: String },
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
    bash_grants: Vec<String>,
    rules: Vec<BashRule>,
}

impl Policy {
    pub fn new(cfg: PolicyConfig) -> Result<Self, PolicyError> {
        // Validate rules: each rule's `match` must be non-empty
        for rule in &cfg.rules {
            if rule.r#match.is_empty() {
                return Err(PolicyError::InvalidRule {
                    id: rule.id.clone(),
                    reason: "empty match pattern".into(),
                });
            }
        }

        let read_deny = cfg
            .read_deny
            .iter()
            .map(|entry| canonicalise_read_deny(&cfg.home, entry))
            .collect();

        // Canonicalize cwd and writable roots so that is_under() comparisons
        // work on macOS where /tmp is a symlink to /private/tmp (PLAN 6.1.1).
        let cwd = canonicalize_or_keep(&cfg.cwd);
        let mut writable_roots: Vec<PathBuf> = vec![cwd.clone()];
        writable_roots.extend(cfg.extra_writable.iter().map(|r| canonicalize_or_keep(r)));

        Ok(Self {
            cwd,
            read_deny,
            protected: cfg.protected,
            writable_roots,
            grants: Vec::new(),
            bash_grants: Vec::new(),
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
        // Check every component, not just the final one (PLAN 6.1.1).
        for component in canonical.components() {
            if let Some(name) = component.as_os_str().to_str() {
                if self.protected.iter().any(|p| p == name) {
                    return (
                        Decision::Ask {
                            reason: format!("protected path: {name}"),
                        },
                        None,
                    );
                }
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

    /// Grant a bash command prefix for the rest of the session.
    /// Commands starting with this prefix are allowed without asking.
    pub fn approve_prefix(&mut self, prefix: &str) {
        self.bash_grants.push(prefix.to_string());
    }

    /// Check a bash command against the rule table. Deny > ask > allow.
    /// Returns the decision and, if a configured rule decided, its id.
    pub fn check_bash(&self, command: &str) -> (Decision, Option<String>) {
        // 1. Deny rules (substring match on the full command)
        // Grants do not override explicit denies.
        let deny_rules = [
            "sudo",
            "su",
            "doas",
            "rm -rf /",
            "rm -rf ~",
            "rm -rf /*",
            "chmod -R 777",
            "chown -R",
            "| sh",
            "| bash",
            "git push --force",
        ];
        for &rule in &deny_rules {
            if command.contains(rule) {
                return (
                    Decision::Deny {
                        reason: format!("command matches deny rule: {rule}"),
                    },
                    None,
                );
            }
        }

        // 2. Session grants: commands matching a granted prefix are allowed.
        for grant in &self.bash_grants {
            if command.starts_with(grant) {
                return (Decision::Allow, Some(format!("grant: {grant}")));
            }
        }

        // 3. Configured rules (exact match on `match` field)
        for rule in &self.rules {
            if command == rule.r#match {
                return (rule.decision.clone(), Some(rule.id.clone()));
            }
        }

        // 3. Dangerous shell constructs → Ask
        let dangerous = ["$(", "`", ">", ">>", "-delete"];
        for &pattern in &dangerous {
            if command.contains(pattern) {
                return (
                    Decision::Ask {
                        reason: format!("command contains dangerous construct: {pattern}"),
                    },
                    None,
                );
            }
        }

        // 4. Split by && || ; and check each segment against allow rules
        let segments: Vec<&str> = command
            .split(&['&', '|', ';'][..])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

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

        // Allow commands that can appear mid-command (e.g. after "timeout N")
        let allow_contains = ["cargo test", "cargo check", "cargo build"];

        for segment in &segments {
            let starts_with_allow = allow_prefixes.iter().any(|&p| segment.starts_with(p));
            let contains_allow = allow_contains.iter().any(|&c| segment.contains(c));
            if !starts_with_allow && !contains_allow {
                return (
                    Decision::Ask {
                        reason: format!("no matching allow rule for segment: {segment}"),
                    },
                    None,
                );
            }
        }

        (Decision::Allow, None)
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

/// Canonicalize `path` if it exists, otherwise return it unchanged.
/// Ensures canonical-form comparisons work on macOS where /tmp -> /private/tmp.
fn canonicalize_or_keep(path: &Path) -> PathBuf {
    if path.exists() {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}
