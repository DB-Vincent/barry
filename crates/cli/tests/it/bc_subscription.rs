#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

// Subscription launchers preserve native CLI behavior without entering Barry's agent.
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

fn launcher(dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    std::fs::write(
        &path,
        "#!/bin/sh\nfor arg do printf '%s\\000' \"$arg\"; done > \"$CAPTURE_ARGS\"\nprintf '%s' \"$BARRY_LAUNCH_PROBE\" > \"$CAPTURE_ENV\"\n/bin/pwd > \"$CAPTURE_CWD\"\nprintf 'native stdout\\n'\nprintf 'native stderr\\n' >&2\n/bin/cat\nexit \"${NATIVE_EXIT:-0}\"\n",
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn command(dir: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.current_dir(dir)
        .env("PATH", dir)
        .env("CAPTURE_ARGS", dir.join("args"))
        .env("CAPTURE_ENV", dir.join("env"))
        .env("CAPTURE_CWD", dir.join("cwd"))
        .env("BARRY_LAUNCH_PROBE", "inherited value")
        .env("BARRY_CONFIG", dir.join("invalid.toml"));
    std::fs::write(dir.join("invalid.toml"), "not valid = [[[").unwrap();
    cmd
}

#[test]
fn bc_subscription_preserves_native_process_interface() {
    for backend in ["codex", "claude"] {
        let dir = tempfile::tempdir().unwrap();
        launcher(dir.path(), backend);
        let marker = dir.path().join("must-not-exist");
        let args = vec![
            OsString::from("--model"),
            OsString::from("a model with spaces"),
            OsString::from(format!("$(touch {}) ; * ' \"", marker.display())),
            OsString::from_vec(vec![b'x', 0xff]),
            OsString::new(),
        ];
        let mut cmd = command(dir.path());
        cmd.args(["subscription", backend, "--"])
            .args(&args)
            .env("NATIVE_EXIT", "37")
            .write_stdin("native input\n")
            .assert()
            .code(37)
            .stdout("native stdout\nnative input\n")
            .stderr("native stderr\n");
        let expected: Vec<u8> = args
            .into_iter()
            .flat_map(|arg| arg.into_vec().into_iter().chain([0]))
            .collect();
        assert_eq!(std::fs::read(dir.path().join("args")).unwrap(), expected);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("env")).unwrap(),
            "inherited value"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cwd"))
                .unwrap()
                .trim(),
            dir.path().canonicalize().unwrap().to_str().unwrap()
        );
        assert!(!marker.exists());
    }
}

#[test]
fn bc_subscription_accepts_empty_native_arguments() {
    for backend in ["codex", "claude"] {
        let dir = tempfile::tempdir().unwrap();
        launcher(dir.path(), backend);
        command(dir.path())
            .args(["subscription", backend])
            .assert()
            .success();
        assert_eq!(
            std::fs::read(dir.path().join("args")).unwrap(),
            Vec::<u8>::new()
        );
    }
}

#[test]
fn bc_subscription_rejects_barry_flags_before_loading_config_or_launching() {
    let flags: &[&[&str]] = &[
        &["-p", "secret prompt"],
        &["--prompt", "secret prompt"],
        &["--json"],
        &["--model", "secret model"],
        &["--resume", "secret session"],
        &["--approval-file", "secret file"],
        &["--max-tokens", "12"],
        &["--max-cost-usd", "1"],
        &["--max-wall-secs", "2"],
        &["--max-bash-secs", "3"],
    ];
    for flag in flags {
        let dir = tempfile::tempdir().unwrap();
        launcher(dir.path(), "codex");
        command(dir.path())
            .args(*flag)
            .args(["subscription", "codex"])
            .assert()
            .code(2)
            .stderr(predicates::str::contains("after --"));
        assert!(!dir.path().join("args").exists());
    }
}

#[test]
fn bc_subscription_rejects_native_flags_without_separator_and_invalid_backend() {
    let dir = tempfile::tempdir().unwrap();
    launcher(dir.path(), "codex");
    for args in [
        vec!["subscription", "codex", "--model", "secret"],
        vec!["subscription", "other"],
    ] {
        command(dir.path()).args(args).assert().code(2);
        assert!(!dir.path().join("args").exists());
    }
}

#[test]
fn bc_subscription_reports_missing_and_unexecutable_cli_without_native_arguments() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args(["subscription", "codex", "--", "secret"])
        .assert()
        .code(127)
        .stderr(predicates::str::contains("Install"))
        .stderr(predicates::str::contains("codex"));
    let path = dir.path().join("codex");
    std::fs::write(&path, "not executable").unwrap();
    let output = command(dir.path())
        .args(["subscription", "codex", "--", "secret"])
        .assert()
        .code(126)
        .get_output()
        .clone();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
}

#[test]
fn bc_subscription_help_explains_native_security_boundary() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args(["subscription", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("tools and approvals"))
        .stdout(predicates::str::contains(
            "policy, sandbox, audit and budgets",
        ));
}

#[test]
fn bc_subscription_preserves_native_signal_termination() {
    use std::os::unix::process::ExitStatusExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("codex");
    std::fs::write(&path, "#!/bin/sh\nkill -TERM $$\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = command(dir.path())
        .args(["subscription", "codex"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(output.status.signal(), Some(15));
}
