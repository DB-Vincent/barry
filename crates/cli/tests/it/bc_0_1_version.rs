/// BC-0.1 Given no arguments except --version,
/// when barry is invoked, then it prints `barry <semver>` and exits 0.
#[test]
fn bc_0_1_version_prints_semver_and_exits_zero() {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("barry 0.1.0"));
}
