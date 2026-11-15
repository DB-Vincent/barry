/// Grants live in `SessionGrants`, not in `Policy`: the policy is unchanged by
/// approvals, and each `SessionGrants` is independent.
use barry_policy::{Decision, Policy, PolicyConfig, SessionGrants};
use barry_testkit::Workspace;

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
fn dir_grant_allows_outside_write_only_with_that_grants_object() {
    let ws = Workspace::new();
    let policy = policy(&ws);
    let target = ws.outside().join("f.txt");

    let mut grants = SessionGrants::new();
    let (before, offered) = policy.check_write(&target, &grants);
    assert!(matches!(before, Decision::Ask { .. }));
    let dir = offered.expect("a grant dir is offered");

    grants.grant_dir(&policy, &dir).unwrap();
    assert!(grants.is_granted(&policy, &target));
    assert_eq!(policy.check_write(&target, &grants).0, Decision::Allow);

    // A fresh SessionGrants, and the policy itself, carry nothing over.
    let fresh = SessionGrants::new();
    assert!(!fresh.is_granted(&policy, &target));
    assert!(matches!(
        policy.check_write(&target, &fresh).0,
        Decision::Ask { .. }
    ));
    assert!(policy
        .writable_roots()
        .iter()
        .all(|r| !target.starts_with(r)));
}

#[test]
fn prefix_grant_is_scoped_to_its_session_grants() {
    let ws = Workspace::new();
    let policy = policy(&ws);

    let mut grants = SessionGrants::new();
    assert!(matches!(
        policy.check_bash("mytool run", &grants).0,
        Decision::Ask { .. }
    ));
    grants.approve_prefix("mytool");
    assert_eq!(policy.check_bash("mytool run", &grants).0, Decision::Allow);
    assert!(matches!(
        policy.check_bash("mytool run", &SessionGrants::new()).0,
        Decision::Ask { .. }
    ));
}

#[test]
fn grants_never_override_deny_rules() {
    let ws = Workspace::new();
    let policy = policy(&ws);
    let mut grants = SessionGrants::new();
    grants.approve_prefix("sudo");
    assert!(matches!(
        policy.check_bash("sudo ls", &grants).0,
        Decision::Deny { .. }
    ));
}
