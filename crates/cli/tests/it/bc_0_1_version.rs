#![allow(clippy::unwrap_used, clippy::expect_used)]

/// BC-0.1 Given no arguments except --version,
/// when barry is invoked, then it prints `barry <semver>` and exits 0.
#[test]
fn bc_0_1_version_prints_semver_and_exits_zero() {
    // Taken from this package's own manifest at compile time. Hard-coding
    // "0.1.0" made the test fail on the release commit that bumps the version,
    // and on every pull request tested against that commit.
    let expected = format!("barry {}", env!("CARGO_PKG_VERSION"));
    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains(expected));
}
