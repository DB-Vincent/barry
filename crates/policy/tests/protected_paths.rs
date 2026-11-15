//! Protected paths (issue #16): every protected name is collected under every
//! writable root, including nested repositories, not just `cwd/.git`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_policy::{Policy, PolicyConfig};
use barry_testkit::Workspace;
use std::path::{Path, PathBuf};

/// The policy canonicalises its writable roots, so a collected path is the
/// canonical form. On macOS /var is a symlink to /private/var, and a
/// comparison against the raw temporary path fails there.
fn canon(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonicalise")
}

fn policy(ws: &Workspace, extra: Vec<PathBuf>, protected: &[&str]) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: extra,
        read_deny: vec![],
        protected: protected
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        rules: vec![],
        network: false,
    })
    .expect("policy constructs")
}

#[test]
fn nested_repositories_are_protected() {
    let ws = Workspace::new();
    let nested = ws.cwd().join("vendor/lib/.git");
    std::fs::create_dir_all(nested.join("objects")).expect("nested repo");

    let policy = policy(&ws, vec![], &[".git"]);
    let paths = policy.protected_paths();

    assert!(
        paths.contains(&canon(&ws.cwd().join(".git"))),
        "the top-level .git must stay protected"
    );
    assert!(
        paths.contains(&canon(&nested)),
        "a submodule/vendored .git must be protected too: {paths:?}"
    );
}

#[test]
fn extra_writable_roots_are_protected() {
    let ws = Workspace::new();
    let extra = ws.home().join("shared");
    std::fs::create_dir_all(&extra).expect("extra root");
    std::fs::write(extra.join(".env"), "SECRET=1").expect("env file");

    let policy = policy(&ws, vec![extra.clone()], &[".env"]);
    assert!(
        policy
            .protected_paths()
            .contains(&canon(&extra.join(".env"))),
        "protected names must be found under extra writable roots"
    );
}

#[test]
fn protected_names_match_any_depth() {
    let ws = Workspace::new();
    let deep = ws.cwd().join("crates/app/config/.envrc");
    std::fs::create_dir_all(deep.parent().expect("parent")).expect("deep dir");
    std::fs::write(&deep, "export TOKEN=1").expect("envrc");

    let policy = policy(&ws, vec![], &[".envrc"]);
    assert!(
        policy.protected_paths().contains(&canon(&deep)),
        "a protected name below the root must be protected"
    );
}

#[test]
fn protected_directories_are_not_descended_into() {
    let ws = Workspace::new();
    // A `.git` inside `.git` is not a repository; walking it would only cost
    // time over thousands of object files.
    let inner = ws.cwd().join(".git/hooks/.git");
    std::fs::create_dir_all(&inner).expect("inner dir");

    let policy = policy(&ws, vec![], &[".git"]);
    let paths = policy.protected_paths();
    assert!(paths.contains(&canon(&ws.cwd().join(".git"))));
    assert!(
        !paths.contains(&canon(&inner)),
        "the walk must stop at a protected directory"
    );
}
