/// Regression test for the dangling-symlink escape.
///
/// `Path::exists` follows links, so a dangling symlink used to look like a
/// missing component and was appended to the canonical path literally. The
/// result looked like it lived inside cwd, but `std::fs::write` followed the
/// link and created a file outside it.
use barry_policy::{Decision, Policy, PolicyConfig};
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
fn bc_3_5_dangling_symlink_is_denied() {
    let ws = Workspace::new();
    let policy = policy(&ws);

    let escape_target = ws.outside().join("escaped.txt");
    let link = ws.cwd().join("link");
    std::os::unix::fs::symlink(&escape_target, &link).unwrap();
    assert!(!escape_target.exists(), "target must start out missing");

    let (decision, grant) = policy.check_write(&link);

    assert!(
        matches!(decision, Decision::Deny { .. }),
        "a dangling symlink must be denied, got {decision:?}"
    );
    assert!(grant.is_none(), "no grant can make this safe: {grant:?}");
}

#[test]
fn bc_3_5_dangling_symlink_fails_closed_for_reads() {
    let ws = Workspace::new();
    let policy = policy(&ws);

    let escape_target = ws.outside().join("escaped.txt");
    let link = ws.cwd().join("link");
    std::os::unix::fs::symlink(&escape_target, &link).unwrap();

    assert!(matches!(policy.check_read(&link), Decision::Deny { .. }));
}
