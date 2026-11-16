//! Arbitrary command strings through the bash rule table. Must not panic, and
//! a command built around an explicitly denied one must never be allowed.
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

    // The invariant is fail-closed, not `Deny`: a suffix that leaves the line
    // unparseable turns the whole command into `Complex`, which the rule layer
    // answers with `Ask`. `sudo |` is the input that found this.
    let denied = format!("sudo {command}");
    assert!(
        !matches!(policy.check_bash(&denied, &grants).0, Decision::Allow),
        "a denied command was allowed: {denied:?}"
    );
});
