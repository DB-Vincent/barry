//! Property tests for path canonicalisation and the bash rule table.
//!
//! These check invariants over generated input rather than single examples:
//! no allowed write resolves outside the writable roots, `..` never survives
//! canonicalisation, and no command string makes the rule table panic or
//! lifts an explicit deny.

use std::path::{Component, Path, PathBuf};

use proptest::prelude::*;

use crate::{Decision, PathError, Policy, PolicyConfig, SessionGrants, canonicalise, is_under};

/// A project directory with a mix of real files, directories and symlinks,
/// plus a sibling directory outside it that symlinks can point at.
struct Fixture {
    _root: tempfile::TempDir,
    cwd: PathBuf,
    outside: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let cwd = base.join("project");
        let outside = base.join("outside");
        std::fs::create_dir_all(cwd.join("a/b")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(cwd.join("a/b/file"), "").unwrap();
        std::fs::write(cwd.join("secret"), "").unwrap();
        std::fs::write(outside.join("file"), "").unwrap();
        // A symlink to a directory outside the project, one inside it, and
        // one to a file inside it.
        std::os::unix::fs::symlink(&outside, cwd.join("link_out")).unwrap();
        std::os::unix::fs::symlink(cwd.join("a"), cwd.join("link_in")).unwrap();
        std::os::unix::fs::symlink(cwd.join("secret"), cwd.join("link_secret")).unwrap();
        Self {
            _root: root,
            cwd,
            outside,
        }
    }

    fn policy(&self, read_deny: Vec<String>) -> Policy {
        Policy::new(PolicyConfig {
            cwd: self.cwd.clone(),
            home: self.cwd.clone(),
            extra_writable: vec![],
            read_deny,
            protected: vec![],
            rules: vec![],
            network: false,
        })
        .unwrap()
    }
}

/// Path segments that hit existing files, symlinks, missing names, `.`,
/// and names with odd characters. `..` is added separately.
fn segment() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "a",
        "b",
        "file",
        "secret",
        "new",
        "link_out",
        "link_in",
        "link_secret",
        ".",
        "",
        "x y",
        "-rf",
        "\u{e9}",
    ])
}

fn relative_path() -> impl Strategy<Value = String> {
    prop::collection::vec(segment(), 1..7).prop_map(|segments| segments.join("/"))
}

/// Independent oracle: resolve the longest existing prefix with the standard
/// library and append the rest. Valid only for paths without `..`.
fn resolve(cwd: &Path, path: &str) -> PathBuf {
    // `Path::components` drops `.` segments, which the filesystem would not
    // accept after a file (`file/.` is ENOTDIR).
    let full: PathBuf = cwd.join(path).components().collect();
    let mut existing = full.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        rest.push(existing.file_name().unwrap().to_os_string());
        existing.pop();
    }
    let mut resolved = std::fs::canonicalize(existing).unwrap();
    for part in rest.into_iter().rev() {
        resolved.push(part);
    }
    resolved
}

#[test]
fn canonicalise_never_returns_dotdot() {
    let fx = Fixture::new();
    proptest!(|(path in "[a-z./ ]{0,24}")| {
        if let Ok(result) = canonicalise(&fx.cwd, Path::new(&path)) {
            prop_assert!(!result.components().any(|c| matches!(c, Component::ParentDir)));
        }
    });
}

#[test]
fn any_dotdot_component_is_rejected() {
    let fx = Fixture::new();
    proptest!(|(
        before in prop::collection::vec(segment(), 0..4),
        after in prop::collection::vec(segment(), 0..4),
    )| {
        let mut parts = before.clone();
        parts.push("..");
        parts.extend(after);
        let path = parts.join("/");
        let result = canonicalise(&fx.cwd, Path::new(&path));
        prop_assert!(
            matches!(result, Err(PathError::DotDot { .. })),
            "{path:?} gave {result:?}"
        );
    });
}

#[test]
fn canonicalise_matches_the_filesystem() {
    let fx = Fixture::new();
    proptest!(|(path in relative_path())| {
        let got = canonicalise(&fx.cwd, Path::new(&path)).unwrap();
        prop_assert_eq!(got, resolve(&fx.cwd, &path), "path {:?}", path);
    });
}

#[test]
fn allowed_writes_resolve_inside_the_project() {
    let fx = Fixture::new();
    let policy = fx.policy(vec![]);
    proptest!(|(path in relative_path())| {
        let (decision, _) = policy.check_write(Path::new(&path), &SessionGrants::new());
        if matches!(decision, Decision::Allow) {
            let real = resolve(&fx.cwd, &path);
            prop_assert!(
                is_under(&real, &fx.cwd),
                "{path:?} was allowed but resolves to {real:?}"
            );
        }
    });
}

#[test]
fn writes_through_an_outside_symlink_are_never_allowed() {
    let fx = Fixture::new();
    let policy = fx.policy(vec![]);
    proptest!(|(tail in prop::collection::vec(segment(), 0..4))| {
        let path = format!("link_out/{}", tail.join("/"));
        let (decision, _) = policy.check_write(Path::new(&path), &SessionGrants::new());
        prop_assert!(
            !matches!(decision, Decision::Allow),
            "{path:?} escapes to {:?} but was allowed",
            fx.outside
        );
    });
}

#[test]
fn read_deny_holds_through_symlinks() {
    let fx = Fixture::new();
    let policy = fx.policy(vec![fx.cwd.join("secret").display().to_string()]);
    proptest!(|(path in relative_path())| {
        let real = resolve(&fx.cwd, &path);
        if is_under(&real, &fx.cwd.join("secret")) {
            prop_assert!(
                matches!(policy.check_read(Path::new(&path)), Decision::Deny { .. }),
                "{path:?} resolves to the denied path but was readable"
            );
        }
    });
}

/// Regression test for review finding #11: a symlink inside the project that
/// points at a missing target outside it must not be writable, or the write
/// would follow the link out of the project.
#[test]
fn dangling_symlink_to_outside_is_not_writable() {
    let fx = Fixture::new();
    std::os::unix::fs::symlink(fx.outside.join("missing"), fx.cwd.join("dangling")).unwrap();
    let policy = fx.policy(vec![]);
    let (decision, _) = policy.check_write(Path::new("dangling"), &SessionGrants::new());
    assert!(!matches!(decision, Decision::Allow));
}

const DENIED_PREFIXES: [&str; 4] = ["sudo ", "doas ", "rm -rf / ", "git push --force "];

fn fresh_policy() -> Policy {
    Policy::new(PolicyConfig {
        cwd: std::env::temp_dir(),
        home: std::env::temp_dir(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: false,
    })
    .unwrap()
}

proptest! {
    #[test]
    fn check_bash_never_panics(command in any::<String>()) {
        let _ = fresh_policy().check_bash(&command, &SessionGrants::new());
    }

    #[test]
    fn denied_commands_stay_denied(
        prefix in prop::sample::select(DENIED_PREFIXES.to_vec()),
        tail in any::<String>(),
        lead in "(ls|echo hi|cat x)( && | ; | \\|\\| )",
        granted in any::<bool>(),
    ) {
        let policy = fresh_policy();
        let mut grants = SessionGrants::new();
        if granted {
            // A session grant must not lift an explicit deny.
            grants.approve_prefix(prefix.split_whitespace().map(str::to_string).collect());
            grants.approve_prefix(vec!["ls".to_string()]);
        }
        for command in [format!("{prefix}{tail}"), format!("{lead}{prefix}{tail}")] {
            let (decision, _) = policy.check_bash(&command, &grants);
            // A command the parser cannot read is asked about, never allowed;
            // everything it can read keeps the explicit deny.
            let unreadable = matches!(
                &decision,
                Decision::Ask { reason } if reason.contains("cannot be analysed")
            );
            prop_assert!(
                matches!(decision, Decision::Deny { .. }) || unreadable,
                "{command:?} was not denied: {decision:?}"
            );
        }
    }

    #[test]
    fn allowed_commands_have_no_redirect_or_substitution(command in any::<String>()) {
        let (decision, _) = fresh_policy().check_bash(&command, &SessionGrants::new());
        if matches!(decision, Decision::Allow) {
            for construct in ["$(", "`", ">", "-delete"] {
                prop_assert!(
                    !command.contains(construct),
                    "{command:?} was allowed but contains {construct:?}"
                );
            }
        }
    }
}
