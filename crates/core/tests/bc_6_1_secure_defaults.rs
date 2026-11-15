//! BC-6.1 / #10 The defaults deny instead of allowing: credential directories
//! are read-denied, protected path components ask, and bash has no network.
use barry_core::config::Config;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::Decision;
use barry_testkit::Workspace;

/// Build a policy exactly as the CLI does when no config file says otherwise.
fn default_policy(ws: &Workspace) -> Policy {
    let cfg = Config::default();
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: cfg.fs_read_deny.clone(),
        protected: cfg.fs_protected.clone(),
        rules: vec![],
        network: cfg.sandbox_network,
    })
    .expect("policy constructs")
}

#[test]
fn a_credential_file_is_read_denied_by_default() {
    let ws = Workspace::new();
    let policy = default_policy(&ws);
    let key = ws.home().join(".ssh/id_test");
    assert!(key.exists(), "the workspace seeds a fake private key");

    let decision = policy.check_read(&key);

    assert!(
        matches!(&decision, Decision::Deny { reason } if reason.contains("read-denied")),
        "reading a private key must not reach the model, got {decision:?}"
    );
}

#[test]
fn a_protected_path_asks_by_default() {
    let ws = Workspace::new();
    let policy = default_policy(&ws);
    let env_file = ws.cwd().join(".env");
    std::fs::write(&env_file, "SECRET=1\n").expect("write .env");

    let (decision, _) = policy.check_write(&env_file);

    assert!(
        matches!(&decision, Decision::Ask { reason } if reason.contains("protected")),
        "writing .env must ask, got {decision:?}"
    );
}

#[test]
fn the_git_directory_asks_by_default() {
    let ws = Workspace::new();
    let policy = default_policy(&ws);
    let config = ws.cwd().join(".git/config");
    std::fs::create_dir_all(config.parent().expect("parent")).expect("mkdir .git");
    std::fs::write(&config, "[core]\n").expect("write .git/config");

    let (decision, _) = policy.check_write(&config);

    assert!(
        matches!(&decision, Decision::Ask { reason } if reason.contains("protected")),
        "writing .git/config must ask, got {decision:?}"
    );
}

#[test]
fn bash_has_no_network_by_default() {
    assert!(
        !Config::default().sandbox_network,
        "network access is opt-in (PLAN 6.1)"
    );
}
