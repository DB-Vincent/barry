//! #26 A config typo is an error, not a silently ignored setting.
//!
//! The parser used to read the TOML by hand, so `read_denny = [...]` looked
//! like no setting at all and the credential paths were quietly unprotected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use predicates::prelude::*;

fn barry() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").expect("barry binary");
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

/// Run `barry rules check ls` against `body` as the config file.
fn check(body: &str) -> assert_cmd::assert::Assert {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, body).expect("write config");

    let mut cmd = barry();
    cmd.env("BARRY_CONFIG", &config)
        .args(["rules", "check", "ls"]);
    cmd.assert()
}

#[test]
fn misspelled_fs_key_is_an_error() {
    check("[fs]\nread_denny = [\"~/.ssh\"]\n")
        .code(2)
        .stderr(predicate::str::contains("config error"))
        .stderr(predicate::str::contains("read_denny"));
}

#[test]
fn misspelled_sandbox_key_is_an_error() {
    check("[sandbox]\nnetwrok = true\n")
        .code(2)
        .stderr(predicate::str::contains("netwrok"));
}

#[test]
fn unknown_top_level_key_is_an_error() {
    check("defualt_model = \"gpt\"\n")
        .code(2)
        .stderr(predicate::str::contains("defualt_model"));
}

#[test]
fn unknown_rule_key_is_an_error() {
    check("[[rule]]\nid = \"r\"\nmatch = \"ls\"\ndecision = \"allow\"\ndescripton = \"why\"\n")
        .code(2)
        .stderr(predicate::str::contains("descripton"));
}

#[test]
fn hook_without_a_command_is_an_error() {
    check("[[hooks.PreToolUse]]\nmatcher = \"bash\"\n")
        .code(2)
        .stderr(predicate::str::contains("command"));
}

#[test]
fn a_complete_config_still_loads() {
    check(concat!(
        "[sandbox]\nnetwork = false\n",
        "[fs]\nread_deny = []\nprotected = [\".git\"]\n",
        "[redaction]\ntool_output = true\n",
        "[[rule]]\nid = \"no-ls-rule\"\nmatch = \"ls -la\"\ndecision = \"deny\"\n",
        "[[hooks.PreToolUse]]\nmatcher = \"bash\"\ncommand = [\"true\"]\n",
    ))
    .success()
    .stdout(predicate::str::contains("allow"));
}
