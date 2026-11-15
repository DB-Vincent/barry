/// BC-3.11 A config rule whose `match` example does not match makes startup
/// fail, with a message naming the rule id.
use barry_policy::{Decision, Policy, PolicyConfig};

#[test]
fn bc_3_11_invalid_rule_match_fails_startup() {
    let cfg = PolicyConfig {
        cwd: std::path::PathBuf::from("/tmp/barry-test-cwd"),
        home: std::path::PathBuf::from("/tmp/barry-test-home"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![barry_policy::BashRule {
            id: "bad-rule".to_string(),
            r#match: "".to_string(),
            decision: Decision::Allow,
        }],
        network: true,
    };

    let result = Policy::new(cfg);
    assert!(result.is_err(), "empty match should fail startup");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("bad-rule"),
        "error should name the rule id: {err}"
    );
}

#[test]
fn bc_3_11_valid_rule_matches_startup() {
    let cfg = PolicyConfig {
        cwd: std::path::PathBuf::from("/tmp/barry-test-cwd"),
        home: std::path::PathBuf::from("/tmp/barry-test-home"),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![barry_policy::BashRule {
            id: "good-rule".to_string(),
            r#match: "npm install foo".to_string(),
            decision: Decision::Allow,
        }],
        network: true,
    };

    let result = Policy::new(cfg);
    assert!(result.is_ok(), "valid match should succeed: {result:?}");
}
