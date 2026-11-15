//! A non-interactive approver driven by a declarative file, for headless and
//! autonomous runs.
//!
//! The file lists the only actions that may be approved. Everything else is
//! denied: there is no "allow by default" and no way to write one.
//!
//! ```toml
//! [[allow]]
//! id = "build"              # optional, shown in the audit log
//! tool = "bash"
//! command = "cargo build"   # the whole command, word for word
//!
//! [[allow]]
//! tool = "write"            # or "edit"
//! path_under = "/tmp/out"   # relative paths resolve against the cwd
//! ```
//!
//! The approver is only asked about actions the policy would otherwise put to
//! the user, so deny rules, read-deny paths and the sandbox still apply. It
//! adds three limits of its own:
//!
//! - A bash command matches only if it is plain words: no quotes, expansion,
//!   redirection, pipes, `;` or `&`. `cargo test; rm x` never matches `cargo
//!   test`.
//! - A path under a protected component (such as `.git`) is never approved.
//! - A request to widen the sandbox after a blocked command is never approved.
//!
//! An approval covers one action. It does not grant a command prefix or a
//! directory for the rest of the session.

use std::path::{Path, PathBuf};

use barry_policy::{canonicalise, is_under};
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy};
use serde::Deserialize;

use crate::{Approver, BoxFuture, CoreError};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSchema {
    #[serde(default)]
    allow: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: Option<String>,
    tool: String,
    command: Option<String>,
    #[serde(default)]
    allow_extra_args: bool,
    path_under: Option<String>,
}

#[derive(Debug)]
enum Matcher {
    Bash {
        words: Vec<String>,
        allow_extra_args: bool,
    },
    Path {
        tool: String,
        root: PathBuf,
    },
}

#[derive(Debug)]
struct Rule {
    id: String,
    matcher: Matcher,
}

/// Approves only what a policy file lists, and denies the rest.
#[derive(Debug)]
pub struct PolicyFileApprover {
    cwd: PathBuf,
    protected: Vec<String>,
    rules: Vec<Rule>,
}

/// Split a bash command into plain words, or `None` if it contains anything
/// the shell would interpret.
fn plain_words(command: &str) -> Option<Vec<&str>> {
    let ok = command.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '\t' | '_' | '-' | '.' | '/' | '=' | ':' | ',' | '@' | '+' | '%'
            )
    });
    if !ok {
        return None;
    }
    let words: Vec<&str> = command.split_whitespace().collect();
    if words.is_empty() { None } else { Some(words) }
}

impl PolicyFileApprover {
    /// Parse a policy file. `cwd` anchors relative `path_under` entries and
    /// `protected` lists path components that are never approved.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Config`] if the file is not valid TOML, has an
    /// unknown key, or contains a malformed rule.
    pub fn from_toml(
        source: &str,
        label: &str,
        cwd: &Path,
        protected: Vec<String>,
    ) -> Result<Self, CoreError> {
        let schema: FileSchema = toml::from_str(source)
            .map_err(|err| CoreError::Config(format!("approval file {label}: {err}")))?;
        let bad = |index: usize, why: &str| {
            CoreError::Config(format!(
                "approval file {label}: allow #{}: {why}",
                index + 1
            ))
        };

        let mut rules = Vec::new();
        for (index, raw) in schema.allow.into_iter().enumerate() {
            let id = raw.id.unwrap_or_else(|| format!("allow-{}", index + 1));
            let matcher = match raw.tool.as_str() {
                "bash" => {
                    if raw.path_under.is_some() {
                        return Err(bad(index, "path_under does not apply to bash"));
                    }
                    let command = raw
                        .command
                        .ok_or_else(|| bad(index, "bash rule needs `command`"))?;
                    let words = plain_words(&command).ok_or_else(|| {
                        bad(
                            index,
                            "command must be plain words (no quotes, expansion, pipes or redirects)",
                        )
                    })?;
                    Matcher::Bash {
                        words: words.into_iter().map(str::to_string).collect(),
                        allow_extra_args: raw.allow_extra_args,
                    }
                }
                tool @ ("write" | "edit") => {
                    if raw.command.is_some() || raw.allow_extra_args {
                        return Err(bad(
                            index,
                            "command and allow_extra_args apply to bash only",
                        ));
                    }
                    let dir = raw
                        .path_under
                        .ok_or_else(|| bad(index, "write and edit rules need `path_under`"))?;
                    let root = canonicalise(cwd, Path::new(&dir))
                        .map_err(|err| bad(index, &format!("path_under: {err}")))?;
                    Matcher::Path {
                        tool: tool.to_string(),
                        root,
                    }
                }
                other => {
                    return Err(bad(
                        index,
                        &format!("unknown tool {other:?} (expected bash, write or edit)"),
                    ));
                }
            };
            rules.push(Rule { id, matcher });
        }

        Ok(Self {
            cwd: cwd.to_path_buf(),
            protected,
            rules,
        })
    }

    /// Read and parse a policy file.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the file cannot be read or parsed.
    pub fn from_file(path: &Path, cwd: &Path, protected: Vec<String>) -> Result<Self, CoreError> {
        let source = std::fs::read_to_string(path).map_err(|err| {
            CoreError::Config(format!(
                "cannot read approval file {}: {err}",
                path.display()
            ))
        })?;
        Self::from_toml(&source, &path.display().to_string(), cwd, protected)
    }

    /// The id of the first rule that approves `req`, if any.
    fn matching_rule(&self, req: &ApprovalRequest) -> Option<&str> {
        match req.tool.as_str() {
            "bash" => {
                // A grant request follows a command the sandbox blocked.
                // Approving it would widen the sandbox, which a file of
                // per-command rules must not do.
                if req.grant_path.is_some() {
                    return None;
                }
                let words = plain_words(req.command.as_deref()?)?;
                self.rules
                    .iter()
                    .find(|rule| match &rule.matcher {
                        Matcher::Bash {
                            words: want,
                            allow_extra_args,
                        } => {
                            words.len() >= want.len()
                                && words.iter().zip(want).all(|(a, b)| *a == b.as_str())
                                && (*allow_extra_args || words.len() == want.len())
                        }
                        Matcher::Path { .. } => false,
                    })
                    .map(|rule| rule.id.as_str())
            }
            tool @ ("write" | "edit") => {
                let canonical = canonicalise(&self.cwd, req.path.as_deref()?).ok()?;
                let protected = canonical.components().any(|c| {
                    c.as_os_str()
                        .to_str()
                        .is_some_and(|name| self.protected.iter().any(|p| p == name))
                });
                if protected {
                    return None;
                }
                self.rules
                    .iter()
                    .find(|rule| match &rule.matcher {
                        Matcher::Path { tool: t, root } => {
                            t == tool
                                && is_under(&canonical, root)
                                // The session grant offered for the file's
                                // directory must also stay inside the rule.
                                && req.grant_path.as_deref().is_none_or(|g| is_under(g, root))
                        }
                        Matcher::Bash { .. } => false,
                    })
                    .map(|rule| rule.id.as_str())
            }
            _ => None,
        }
    }
}

impl Approver for PolicyFileApprover {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice> {
        let choice = self.decide_now(req).0;
        Box::pin(async move { choice })
    }

    fn decide_attributed(
        &self,
        req: &ApprovalRequest,
    ) -> BoxFuture<'_, (ApprovalChoice, DecidedBy)> {
        let decision = self.decide_now(req);
        Box::pin(async move { decision })
    }
}

impl PolicyFileApprover {
    fn decide_now(&self, req: &ApprovalRequest) -> (ApprovalChoice, DecidedBy) {
        match self.matching_rule(req) {
            Some(id) => (
                ApprovalChoice::Once,
                DecidedBy::Rule(format!("approval-file:{id}")),
            ),
            None => (ApprovalChoice::Deny, DecidedBy::Default),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str, command: Option<&str>, path: Option<&str>) -> ApprovalRequest {
        ApprovalRequest {
            id: "1".into(),
            tool: tool.into(),
            summary: String::new(),
            reason: String::new(),
            grant_path: None,
            command: command.map(str::to_string),
            path: path.map(PathBuf::from),
        }
    }

    fn approver(toml: &str) -> PolicyFileApprover {
        PolicyFileApprover::from_toml(toml, "test", Path::new("/work"), vec![".git".into()])
            .expect("valid")
    }

    #[test]
    fn plain_words_rejects_shell_syntax() {
        for bad in [
            "a; b", "a && b", "a | b", "a > f", "$(x)", "`x`", "a 'b'", "a\nb", "~", "*", "", "  ",
        ] {
            assert!(plain_words(bad).is_none(), "{bad:?}");
        }
        assert_eq!(
            plain_words("cargo  test -p x"),
            Some(vec!["cargo", "test", "-p", "x"])
        );
    }

    #[test]
    fn empty_file_denies_everything() {
        let a = approver("");
        assert!(a.matching_rule(&req("bash", Some("ls"), None)).is_none());
    }

    #[test]
    fn bash_rule_matches_the_exact_command_only() {
        let a = approver("[[allow]]\ntool='bash'\ncommand='cargo build'\n");
        assert!(
            a.matching_rule(&req("bash", Some("cargo build"), None))
                .is_some()
        );
        assert!(
            a.matching_rule(&req("bash", Some("cargo   build"), None))
                .is_some()
        );
        assert!(
            a.matching_rule(&req("bash", Some("cargo build --release"), None))
                .is_none()
        );
        assert!(
            a.matching_rule(&req("bash", Some("cargo build; rm x"), None))
                .is_none()
        );
        assert!(
            a.matching_rule(&req("bash", Some("cargo buildx"), None))
                .is_none()
        );
    }

    #[test]
    fn extra_args_are_opt_in() {
        let a = approver("[[allow]]\ntool='bash'\ncommand='cargo test'\nallow_extra_args=true\n");
        assert!(
            a.matching_rule(&req("bash", Some("cargo test -p core"), None))
                .is_some()
        );
        assert!(
            a.matching_rule(&req("bash", Some("cargo test && x"), None))
                .is_none()
        );
        assert!(a.matching_rule(&req("bash", Some("cargo"), None)).is_none());
    }

    #[test]
    fn sandbox_grant_requests_are_never_approved() {
        let a = approver("[[allow]]\ntool='bash'\ncommand='cargo build'\n");
        let mut r = req("bash", Some("cargo build"), None);
        r.grant_path = Some(PathBuf::from("/tmp"));
        assert!(a.matching_rule(&r).is_none());
    }

    #[test]
    fn write_rule_needs_the_path_inside_the_root_and_the_right_tool() {
        let a = approver("[[allow]]\ntool='write'\npath_under='/work/out'\n");
        assert!(
            a.matching_rule(&req("write", None, Some("out/a.txt")))
                .is_some()
        );
        assert!(
            a.matching_rule(&req("write", None, Some("/work/out/x/a.txt")))
                .is_some()
        );
        assert!(
            a.matching_rule(&req("edit", None, Some("out/a.txt")))
                .is_none()
        );
        assert!(
            a.matching_rule(&req("write", None, Some("src/a.txt")))
                .is_none()
        );
        assert!(
            a.matching_rule(&req("write", None, Some("out/../src/a.txt")))
                .is_none()
        );
    }

    #[test]
    fn protected_components_are_never_approved() {
        let a = approver("[[allow]]\ntool='write'\npath_under='/work'\n");
        assert!(
            a.matching_rule(&req("write", None, Some(".git/config")))
                .is_none()
        );
        assert!(
            a.matching_rule(&req("write", None, Some("a/.git/hooks/x")))
                .is_none()
        );
    }

    #[test]
    fn a_grant_wider_than_the_rule_is_refused() {
        let a = approver("[[allow]]\ntool='write'\npath_under='/work/out'\n");
        let mut r = req("write", None, Some("/work/out/a.txt"));
        r.grant_path = Some(PathBuf::from("/work"));
        assert!(a.matching_rule(&r).is_none());
        r.grant_path = Some(PathBuf::from("/work/out"));
        assert!(a.matching_rule(&r).is_some());
    }

    #[test]
    fn invalid_files_are_rejected() {
        for bad in [
            "[[allow]]\ntool='bash'\n",
            "[[allow]]\ntool='bash'\ncommand='a | b'\n",
            "[[allow]]\ntool='write'\n",
            "[[allow]]\ntool='read'\npath_under='/x'\n",
            "[[allow]]\ntool='bash'\ncommand='ls'\ntypo=1\n",
            "[[allow]]\ntool='write'\npath_under='../x'\n",
            "[[allow]]\ntool='bash'\ncommand='ls'\npath_under='/x'\n",
            "allow = 'yes'\n",
            "default = 'allow'\n",
        ] {
            assert!(
                PolicyFileApprover::from_toml(bad, "t", Path::new("/work"), vec![]).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn decisions_name_the_rule() {
        let a = approver("[[allow]]\nid='b'\ntool='bash'\ncommand='ls'\n");
        let (choice, by) = a.decide_now(&req("bash", Some("ls"), None));
        assert_eq!(choice, ApprovalChoice::Once);
        assert_eq!(by, DecidedBy::Rule("approval-file:b".into()));
        let (choice, by) = a.decide_now(&req("bash", Some("pwd"), None));
        assert_eq!(choice, ApprovalChoice::Deny);
        assert_eq!(by, DecidedBy::Default);
    }
}
