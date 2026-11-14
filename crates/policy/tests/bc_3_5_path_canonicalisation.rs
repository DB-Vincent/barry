/// BC-3.5: `../x` and a symlink inside cwd that points outside are both
/// treated as outside cwd.
///
/// The canonicalisation must reject `..` components and resolve symlinks,
/// so that neither escape hatch reaches a path inside cwd.
use barry_policy::{Decision, Policy, PolicyConfig};
use barry_testkit::Workspace;

fn default_config(ws: &Workspace) -> PolicyConfig {
    PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    }
}

#[test]
fn bc_3_5_dotdot_path_is_treated_as_outside_cwd() {
    let ws = Workspace::new();
    let policy = Policy::new(default_config(&ws)).unwrap();

    // cwd/../x escapes cwd via `..`; must not be Allow.
    let dotdot = ws.cwd().join("../x");
    let (decision, _grant) = policy.check_write(&dotdot);

    assert!(
        matches!(decision, Decision::Ask { .. }),
        "cwd/../x should be treated as outside cwd (Ask), got {decision:?}"
    );
}

#[test]
fn bc_3_5_symlink_outside_cwd_is_treated_as_outside_cwd() {
    let ws = Workspace::new();
    let policy = Policy::new(default_config(&ws)).unwrap();

    // A symlink inside cwd pointing at outside/ must not let us write through it.
    let link = ws.cwd().join("link");
    std::os::unix::fs::symlink(ws.outside(), &link).unwrap();

    let through_link = link.join("secret.txt");
    let (decision, _grant) = policy.check_write(&through_link);

    assert!(
        matches!(decision, Decision::Ask { .. }),
        "cwd/link/secret.txt (symlink to outside) should be outside cwd (Ask), got {decision:?}"
    );
}

#[test]
fn bc_3_1_path_inside_cwd_is_allowed() {
    let ws = Workspace::new();
    let policy = Policy::new(default_config(&ws)).unwrap();

    // A normal path inside cwd is Allow with no grant needed.
    let inside = ws.file("src/main.rs");
    let (decision, grant) = policy.check_write(&inside);

    assert_eq!(decision, Decision::Allow);
    assert!(grant.is_none(), "inside cwd needs no grant: {grant:?}");
}
