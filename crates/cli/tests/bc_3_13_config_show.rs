//! #27 The config is found without `$BARRY_CONFIG`, and `barry config show`
//! reports the configuration actually in effect.
use predicates::prelude::PredicateBooleanExt;
use std::path::{Path, PathBuf};

fn barry() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").expect("barry binary");
    cmd.env_remove("BARRY_CONFIG");
    cmd
}

/// An empty home and an empty XDG config dir, so whatever the machine running
/// the tests has configured cannot leak into them.
fn isolated(dir: &Path) -> (PathBuf, PathBuf) {
    let home = dir.join("home");
    let xdg = dir.join("xdg");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(xdg.join("barry")).expect("xdg config dir");
    (home, xdg)
}

#[test]
fn xdg_config_is_loaded_without_barry_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, xdg) = isolated(dir.path());
    std::fs::write(
        xdg.join("barry/config.toml"),
        "[fs]\nprotected = [\".custom\"]\n",
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "show"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("fs.protected: .custom"))
        .stdout(predicates::str::contains("barry/config.toml"));
}

#[test]
fn barry_config_wins_over_the_xdg_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, xdg) = isolated(dir.path());
    std::fs::write(
        xdg.join("barry/config.toml"),
        "[fs]\nprotected = [\".from-xdg\"]\n",
    )
    .expect("write xdg config");

    let explicit = dir.path().join("explicit.toml");
    std::fs::write(&explicit, "[sandbox]\nnetwork = true\n").expect("write explicit config");

    let mut cmd = barry();
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("BARRY_CONFIG", &explicit)
        .args(["config", "show"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("sandbox.network: true"))
        .stdout(predicates::str::contains(".from-xdg").not())
        // The untouched sections still show the built-in defaults.
        .stdout(predicates::str::contains("~/.ssh"))
        .stdout(predicates::str::contains(
            "fs.protected: .git, .barry, .env",
        ));
}

#[test]
fn defaults_are_shown_when_no_file_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, xdg) = isolated(dir.path());

    let mut cmd = barry();
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "show"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("config_file: none"))
        .stdout(predicates::str::contains("sandbox.network: false"))
        .stdout(predicates::str::contains("~/.ssh"))
        .stdout(predicates::str::contains("rules: none"))
        .stdout(predicates::str::contains("hooks: none"));
}

#[test]
fn a_broken_xdg_config_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, xdg) = isolated(dir.path());
    std::fs::write(xdg.join("barry/config.toml"), "[fs]\nread_denny = []\n").expect("write config");

    let mut cmd = barry();
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "show"]);
    cmd.assert()
        .code(2)
        .stderr(predicates::str::contains("config error"))
        .stderr(predicates::str::contains("read_denny"));
}

#[test]
fn configured_rules_and_hooks_are_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, xdg) = isolated(dir.path());
    std::fs::write(
        xdg.join("barry/config.toml"),
        concat!(
            "[[rule]]\nid = \"no-ls\"\nmatch = \"ls\"\ndecision = \"deny\"\n",
            "[[hooks.PreToolUse]]\nmatcher = \"bash\"\ncommand = [\"true\"]\nfail_closed = true\n",
        ),
    )
    .expect("write config");

    let mut cmd = barry();
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "show"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("rule: no-ls \"ls\" -> deny"))
        .stdout(predicates::str::contains("hook: bash -> true"))
        .stdout(predicates::str::contains("fail_closed true"));
}
