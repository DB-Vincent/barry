/// BC-0.2 Given no config file, defaults apply,
/// when `barry rules check "ls"` is invoked,
/// then it prints `allow` and exits 0.
#[test]
fn bc_0_2_rules_check_ls_prints_allow() {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.arg("rules").arg("check").arg("ls");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("allow"));
}
