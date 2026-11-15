//! Arbitrary command strings through the bash rule table. Must not panic, and
//! a command that starts with an explicitly denied one must stay denied.
#![no_main]

use barry_policy::{Decision, Policy, PolicyConfig, SessionGrants};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|command: &str| {
    let dir = std::env::temp_dir();
    let policy = Policy::new(PolicyConfig {
        cwd: dir.clone(),
        home: dir,
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: false,
    })
    .expect("a policy without rules is valid");

    let grants = SessionGrants::new();
    let _ = policy.check_bash(command, &grants);
    let denied = format!("sudo {command}");
    assert!(matches!(
        policy.check_bash(&denied, &grants).0,
        Decision::Deny { .. }
    ));
});
