//! BC-3.12 with rules from the config file (issue #18): `[[rule]]` entries are
//! loaded and decide for `barry rules check`, including malformed ones.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use predicates::prelude::*;

fn barry() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").expect("barry binary");
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

#[test]
fn configured_deny_rule_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[[rule]]\nid = \"no-echo\"\nmatch = \"echo hi\"\ndecision = \"deny\"\n",
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "echo hi"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("deny"))
        .stderr(predicate::str::contains("rule: no-echo"));
}

#[test]
fn configured_allow_rule_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[[rule]]\nid = \"tf-plan\"\nmatch = \"terraform plan\"\ndecision = \"allow\"\n",
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "terraform plan"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("allow"))
        .stdout(predicate::str::contains("rule: tf-plan"));
}

#[test]
fn configured_rule_decision_applies_before_the_allowlist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    // `ls` is allow-listed by default; a user deny rule must win.
    std::fs::write(
        &config,
        "[[rule]]\nid = \"no-ls\"\nmatch = \"ls\"\ndecision = \"deny\"\n",
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "ls"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("rule: no-ls"));
}

#[test]
fn unknown_rule_decision_is_a_config_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[[rule]]\nid = \"bad\"\nmatch = \"ls\"\ndecision = \"maybe\"\n",
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "ls"]);
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains("config error"))
        .stderr(predicate::str::contains("unknown decision"));
}

#[test]
fn rule_without_match_is_a_config_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[[rule]]\nid = \"bad\"\ndecision = \"allow\"\n")
        .expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "ls"]);
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains("config error"))
        .stderr(predicate::str::contains("`match`"));
}

/// A configured deny rule also governs a real headless turn, not just
/// `rules check`.
#[tokio::test(flavor = "multi_thread")]
async fn configured_deny_rule_blocks_bash_in_headless() {
    use barry_testkit::{FakeLlm, Reply};
    use serde_json::json;

    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[[rule]]\nid = \"no-echo\"\nmatch = \"echo hi\"\ndecision = \"deny\"\n",
    )
    .expect("write config");

    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "echo hi" }),
        },
        Reply::Text {
            content: "understood".to_string(),
        },
    ])
    .await;

    let mut cmd = barry();
    let out = cmd
        .args(["-p", "say hi"])
        .arg("--json")
        .env("BARRY_CONFIG", &config)
        .env("BARRY_BASE_URL", llm.uri())
        .env(
            "XDG_STATE_HOME",
            std::env::temp_dir().join(format!("barry-rules-state-{}", std::process::id())),
        )
        .current_dir(dir.path())
        .output()
        .expect("barry runs");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let saw_rule = llm.requests().iter().any(|req| {
        req["messages"]
            .as_array()
            .map(|msgs| {
                msgs.iter().any(|m| {
                    m["role"] == "tool"
                        && m["content"]
                            .as_str()
                            .map(|c| c.contains("rule no-echo"))
                            .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });
    assert!(saw_rule, "the model should see the configured deny rule");
}
