//! Authentication delegates only fixed commands to the official native CLIs.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

fn fake_ant(dir: &Path, body: &str) {
    let path = dir.join("ant");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fake_codex(dir: &Path, body: &str) {
    let path = dir.join("codex");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn command(dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").unwrap();
    cmd.current_dir(dir)
        .env("PATH", dir)
        .env("BARRY_CONFIG", dir.join("invalid.toml"))
        .env("BARRY_BASE_URL", "http://127.0.0.1:9")
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("ANTHROPIC_API_KEY", "fake-key-must-not-reach-ant")
        .env("ANTHROPIC_AUTH_TOKEN", "fake-token-must-not-reach-ant")
        .env("ANTHROPIC_PROFILE", "unrelated-profile")
        .env("ANTHROPIC_CONFIG_DIR", dir.join("native-config"));
    std::fs::write(dir.join("invalid.toml"), "not valid = [[[").unwrap();
    cmd
}

#[test]
fn bc_auth_fixed_argv_profile_and_child_environment_without_agent_config() {
    for (args, expected) in [
        (
            vec!["login", "anthropic"],
            "auth\nlogin\n--profile\nbarry\n",
        ),
        (
            vec!["login", "anthropic", "--no-browser"],
            "auth\nlogin\n--profile\nbarry\n--no-browser\n",
        ),
        (
            vec!["status", "anthropic"],
            "auth\nstatus\n--profile\nbarry\n",
        ),
        (
            vec!["logout", "anthropic"],
            "auth\nlogout\n--profile\nbarry\n",
        ),
        (
            vec!["status", "anthropic", "--profile", "default"],
            "auth\nstatus\n--profile\ndefault\n",
        ),
        (
            vec![
                "login",
                "anthropic",
                "--profile",
                "team_1.prod-test",
                "--no-browser",
            ],
            "auth\nlogin\n--profile\nteam_1.prod-test\n--no-browser\n",
        ),
        (
            vec!["logout", "anthropic", "--profile", "default"],
            "auth\nlogout\n--profile\ndefault\n",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        fake_ant(
            dir.path(),
            "printf '%s\\n' \"$@\" > args\nprintf '%s|%s|%s|%s' \"${ANTHROPIC_API_KEY-unset}\" \"${ANTHROPIC_AUTH_TOKEN-unset}\" \"${ANTHROPIC_PROFILE-unset}\" \"$ANTHROPIC_CONFIG_DIR\" > child-env\nprintf 'native auth output\\n'\nprintf 'native auth stderr\\n' >&2\nexit 0",
        );
        command(dir.path())
            .arg("auth")
            .args(args)
            .assert()
            .success()
            .stdout("native auth output\n")
            .stderr("native auth stderr\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("args")).unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("child-env")).unwrap(),
            format!(
                "unset|unset|unset|{}",
                dir.path().join("native-config").display()
            )
        );
        assert!(
            !dir.path().join("state").exists(),
            "auth does not create an agent session"
        );
    }
}

#[test]
fn bc_auth_rejects_run_flags_and_arbitrary_native_commands() {
    let flags: &[&[&str]] = &[
        &["-p", "prompt"],
        &["--json"],
        &["--model", "model"],
        &["--resume", "session"],
        &["--approval-file", "file"],
        &["--max-tokens", "1"],
        &["--max-cost-usd", "1"],
        &["--max-wall-secs", "1"],
        &["--max-bash-secs", "1"],
    ];
    let dir = tempfile::tempdir().unwrap();
    fake_ant(dir.path(), "printf 'called' > called");
    for flag in flags {
        command(dir.path())
            .args(*flag)
            .args(["auth", "status", "anthropic"])
            .assert()
            .code(2);
    }
    for args in [
        vec!["auth", "messages", "anthropic"],
        vec!["auth", "login", "other"],
        vec!["auth", "login", "anthropic", "--", "messages", "create"],
        vec!["auth", "logout", "anthropic", "--all"],
        vec!["auth", "status", "anthropic", "--no-browser"],
        vec!["auth", "status", "anthropic", "$(touch marker)"],
    ] {
        command(dir.path()).args(args).assert().code(2);
    }
    assert!(!dir.path().join("called").exists());
    assert!(!dir.path().join("marker").exists());
}

#[test]
fn bc_auth_invalid_profiles_never_launch_a_child() {
    let dir = tempfile::tempdir().unwrap();
    fake_ant(dir.path(), "printf 'called' > called");
    for profile in [
        "",
        ".",
        "..",
        "../default",
        "team/name",
        "team\\name",
        "with space",
        "with\ttab",
        "-flag",
        "_leading",
        "é",
        &"a".repeat(65),
    ] {
        for action in ["login", "status", "logout"] {
            command(dir.path())
                .args(["auth", action, "anthropic", "--profile", profile])
                .assert()
                .code(2);
        }
    }
    assert!(!dir.path().join("called").exists());
}

#[test]
fn bc_auth_missing_unexecutable_and_native_exit_codes_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args(["auth", "login", "anthropic"])
        .assert()
        .code(127)
        .stderr(predicates::str::contains("brew install anthropics/tap/ant"));
    let path = dir.path().join("ant");
    std::fs::write(&path, "not executable").unwrap();
    command(dir.path())
        .args(["auth", "status", "anthropic"])
        .assert()
        .code(126);
    fake_ant(dir.path(), "exit 37");
    command(dir.path())
        .args(["auth", "status", "anthropic"])
        .assert()
        .code(37);
    fake_ant(dir.path(), "kill -TERM $$");
    command(dir.path())
        .args(["auth", "status", "anthropic"])
        .assert()
        .code(143);
}

#[test]
fn bc_auth_repl_returns_after_auth_and_rejects_invalid_syntax() {
    let dir = tempfile::tempdir().unwrap();
    fake_ant(
        dir.path(),
        "printf '%s\\n' \"$@\" >> args\nprintf 'native auth output\\n'\nexit 37",
    );
    fake_codex(
        dir.path(),
        "printf '%s\\n' \"$@\" >> codex-args\nprintf 'native auth output\\n'\nexit 37",
    );
    let out = command(dir.path()).env("BARRY_CONFIG", dir.path().join("absent.toml"))
        .write_stdin("/auth status anthropic --profile default\n/auth status anthropic --profile ../invalid\n/auth logout anthropic --all\n/auth login anthropic --no-browser\n/auth status codex\n/auth login codex --no-browser\n/auth status codex --profile default\n/grants\n/exit\n")
        .assert().success().get_output().clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("native auth output").count(), 4);
    assert!(String::from_utf8_lossy(&out.stderr).contains("status 37"));
    assert!(
        stdout.contains("no grants this session"),
        "REPL remains usable: {stdout}"
    );
    assert!(
        stdout.contains("/auth login anthropic"),
        "invalid syntax prints usage: {stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("args")).unwrap(),
        "auth\nstatus\n--profile\ndefault\nauth\nlogin\n--profile\nbarry\n--no-browser\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("codex-args")).unwrap(),
        "login\nstatus\nlogin\n--device-auth\n"
    );
}

#[tokio::test]
async fn bc_auth_ctrl_c_kills_child_and_returns_to_repl() {
    for graceful in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let script = if graceful {
            "printf '%s' \"$$\" > auth-pid\nprintf 'auth-child-ready\\n'\n/bin/sleep 0.4\nprintf 'cleaned' > native-cleanup\nexit 130"
        } else {
            "printf '%s' \"$$\" > auth-pid\nprintf 'auth-child-ready\\n'\nexec /bin/sleep 60"
        };
        fake_ant(dir.path(), script);
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
            .current_dir(dir.path())
            .env("PATH", dir.path())
            .env("BARRY_CONFIG", dir.path().join("absent.toml"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"/auth login anthropic\n").await.unwrap();
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(ready, "auth-child-ready");
        let pid = child.id().unwrap();
        assert!(
            std::process::Command::new("/bin/kill")
                .args(["-INT", &pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        stdin.write_all(b"/grants\n/exit\n").await.unwrap();
        drop(stdin);
        let rest = tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                output.push_str(&line);
            }
            output
        })
        .await
        .unwrap();
        assert!(rest.contains("no grants this session"), "{rest}");
        assert!(
            tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        assert!(stderr.contains("status 130"), "{stderr}");
        let auth_pid = std::fs::read_to_string(dir.path().join("auth-pid")).unwrap();
        assert!(
            !std::process::Command::new("/bin/kill")
                .args(["-0", &auth_pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "authentication child must be reaped"
        );
        assert_eq!(dir.path().join("native-cleanup").exists(), graceful);
    }
}

#[test]
fn bc_auth_codex_fixed_commands_and_native_home_without_environment_tokens() {
    for (args, expected) in [
        (vec!["login", "codex"], "login\n"),
        (
            vec!["login", "codex", "--no-browser"],
            "login\n--device-auth\n",
        ),
        (vec!["status", "codex"], "login\nstatus\n"),
        (vec!["logout", "codex"], "logout\n"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        fake_codex(
            dir.path(),
            "printf '%s\\n' \"$@\" > args\nprintf '%s|%s|%s' \"${OPENAI_API_KEY-unset}\" \"${CODEX_ACCESS_TOKEN-unset}\" \"$CODEX_HOME\" > child-env\nprintf 'codex auth output\\n'",
        );
        command(dir.path())
            .arg("auth")
            .args(args)
            .env("OPENAI_API_KEY", "fake-key-must-not-reach-codex")
            .env("CODEX_ACCESS_TOKEN", "fake-token-must-not-reach-codex")
            .env("CODEX_HOME", dir.path().join("native-codex-home"))
            .assert()
            .success()
            .stdout("codex auth output\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("args")).unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("child-env")).unwrap(),
            format!(
                "unset|unset|{}",
                dir.path().join("native-codex-home").display()
            )
        );
        assert!(!dir.path().join("state").exists());
    }
}

#[test]
fn bc_auth_codex_rejects_profiles_tokens_passthrough_and_shell_expansion() {
    let dir = tempfile::tempdir().unwrap();
    fake_codex(dir.path(), "printf 'called' > called");
    for action in ["login", "status", "logout"] {
        command(dir.path())
            .args(["auth", action, "codex", "--profile", "default"])
            .assert()
            .code(2)
            .stderr(predicates::str::contains("--profile"));
    }
    for args in [
        vec!["auth", "login", "codex", "--with-api-key"],
        vec!["auth", "login", "codex", "--with-access-token"],
        vec!["auth", "login", "codex", "--", "exec", "prompt"],
        vec!["auth", "status", "codex", "$(touch marker)"],
        vec!["auth", "logout", "codex", "--all"],
        vec!["auth", "status", "codex", "--no-browser"],
    ] {
        command(dir.path()).args(args).assert().code(2);
    }
    assert!(!dir.path().join("called").exists());
    assert!(!dir.path().join("marker").exists());
}

#[test]
fn bc_auth_codex_launch_errors_and_native_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args(["auth", "login", "codex"])
        .assert()
        .code(127)
        .stderr(predicates::str::contains("official Codex CLI"));
    std::fs::write(dir.path().join("codex"), "not executable").unwrap();
    command(dir.path())
        .args(["auth", "status", "codex"])
        .assert()
        .code(126);
    fake_codex(dir.path(), "exit 37");
    command(dir.path())
        .args(["auth", "status", "codex"])
        .assert()
        .code(37);
    fake_codex(dir.path(), "kill -TERM $$");
    command(dir.path())
        .args(["auth", "status", "codex"])
        .assert()
        .code(143);
}
