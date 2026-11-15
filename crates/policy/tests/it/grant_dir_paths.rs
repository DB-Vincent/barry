#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Regression tests for `Policy::grant_dir` path resolution.
///
/// A grant is explicit user permission, so `..` is resolved rather than
/// rejected — but it must be resolved from the right base. An absolute path
/// starts at the filesystem root; resolving it from cwd would silently grant a
/// directory the user never approved.
use barry_policy::{Policy, PolicyConfig, SessionGrants};
use barry_testkit::Workspace;
use std::path::Path;

fn policy(ws: &Workspace) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .unwrap()
}

#[test]
fn absolute_grant_with_dotdot_resolves_from_the_root() {
    let ws = Workspace::new();
    let policy = policy(&ws);
    let mut grants = SessionGrants::new();

    let outside = std::fs::canonicalize(ws.outside()).unwrap();
    let dir = outside.join("sub");
    std::fs::create_dir_all(&dir).unwrap();

    // `<outside>/sub/../elsewhere` must resolve to `<outside>/elsewhere`.
    let requested = dir.join("../elsewhere");
    std::fs::create_dir_all(outside.join("elsewhere")).unwrap();
    grants.grant_dir(&policy, &requested).unwrap();

    let expected = std::fs::canonicalize(outside.join("elsewhere")).unwrap();
    assert_eq!(
        grants.dirs(),
        &[expected],
        "absolute grant must not be re-based on cwd"
    );
}

#[test]
fn relative_grant_still_resolves_against_cwd() {
    let ws = Workspace::new();
    let policy = policy(&ws);
    let mut grants = SessionGrants::new();

    grants
        .grant_dir(&policy, Path::new("nested/../granted"))
        .unwrap();

    let expected = std::fs::canonicalize(ws.cwd()).unwrap().join("granted");
    assert_eq!(grants.dirs(), &[expected]);
}

#[test]
fn grant_does_not_create_the_directory() {
    let ws = Workspace::new();
    let policy = policy(&ws);
    let mut grants = SessionGrants::new();

    let target = ws.outside().join("not-created-by-grant");
    grants.grant_dir(&policy, &target).unwrap();

    assert!(
        !target.exists(),
        "granting a path must not create it as a side effect"
    );
}
