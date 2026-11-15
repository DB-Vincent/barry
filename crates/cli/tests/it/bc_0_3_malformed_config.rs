/// BC-0.3 Given a malformed config file,
/// when barry is invoked, then it exits 2 and names the file and line,
/// with no Rust backtrace or panic text on stderr.
use predicates::prelude::PredicateBooleanExt;

#[test]
fn bc_0_3_malformed_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "this is = not = valid toml [[[").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.env("BARRY_CONFIG", &config_path);
    cmd.arg("rules").arg("check").arg("ls");
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains("config error in"))
        .stderr(predicates::str::contains(config_path.to_str().unwrap()))
        .stderr(predicates::str::contains("line"))
        .stderr(
            predicates::str::is_match(r"(?i)backtrace|panicked")
                .unwrap()
                .not(),
        );
}
