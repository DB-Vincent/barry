//! #43 Errors are typed and keep their cause, so callers can match on them and
//! walk `Error::source` instead of parsing a message.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use barry_core::config::{Config, HookConfig};
use barry_core::{Agent, CoreError};
use barry_testkit::{ScriptedApprover, ScriptedProvider};
use std::error::Error;
use std::sync::Arc;

fn config(hooks: Vec<HookConfig>) -> Config {
    Config {
        default_model: "local".to_string(),
        max_turns: 5,
        context_window: 20_000,
        sandbox_network: true,
        sandbox_unsandboxed: false,
        redact_tool_output: false,
        fs_read_deny: vec![],
        fs_protected: vec![],
        rules: vec![],
        hooks,
        budgets: barry_core::budget::Budgets::default(),
    }
}

fn policy() -> barry_policy::Policy {
    barry_policy::Policy::new(barry_policy::PolicyConfig {
        cwd: std::env::temp_dir(),
        home: std::env::temp_dir().join("barry-test-policy-home"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network: true,
    })
    .expect("policy constructs")
}

#[test]
fn invalid_hook_matcher_is_typed_and_keeps_the_regex_error() {
    let hook = HookConfig {
        matcher: "(".to_string(),
        command: vec!["true".to_string()],
        timeout_secs: 1,
        fail_closed: false,
    };
    let result = Agent::new(
        config(vec![hook]),
        Arc::new(ScriptedProvider::new(vec![])),
        Arc::new(ScriptedApprover::new(vec![])),
        policy(),
    );
    let Err(err) = result else {
        panic!("an invalid matcher must be rejected");
    };

    assert!(
        matches!(&err, CoreError::HookMatcher { matcher, .. } if matcher == "("),
        "got {err:?}"
    );
    let cause = err.source().expect("regex error is the source");
    assert!(cause.downcast_ref::<regex::Error>().is_some());
}

#[test]
fn resume_of_a_missing_log_keeps_the_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let result = Agent::resume(
        config(vec![]),
        Arc::new(ScriptedProvider::new(vec![])),
        Arc::new(ScriptedApprover::new(vec![])),
        policy(),
        &dir.path().join("missing.jsonl"),
    );
    let Err(err) = result else {
        panic!("a missing log cannot be resumed");
    };

    assert!(matches!(&err, CoreError::Session(_)), "got {err:?}");
    assert!(err.source().is_some());
}
