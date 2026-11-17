#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

/// `BARRY_PROVIDER=codex` delegates the turn to `codex exec --json`. A fake
/// `codex` on `PATH` records its arguments, stdin and environment and prints
/// the documented JSONL events.
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn fake_codex(dir: &Path, body: &str) {
    let path = dir.join("codex");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn barry(dir: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG");
    cmd.env(
        "XDG_STATE_HOME",
        std::env::temp_dir().join(format!("barry-codex-test-state-{}", std::process::id())),
    );
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path)
        .env("BARRY_PROVIDER", "codex")
        // Codex must not receive API keys that would shadow its stored login.
        .env("OPENAI_API_KEY", "sk-should-not-reach-codex-0123456789")
        .env("CODEX_ACCESS_TOKEN", "should-not-reach-codex");
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_provider_runs_codex_exec_and_prints_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("record");
    fake_codex(
        dir.path(),
        &format!(
            r#"echo "$@" > {r}.args
cat > {r}.stdin
env > {r}.env
echo '{{"type":"thread.started","thread_id":"t"}}'
echo '{{"type":"item.completed","item":{{"id":"1","type":"agent_message","text":"hello from codex"}}}}'
echo '{{"type":"turn.completed","usage":{{"input_tokens":3,"output_tokens":4}}}}'"#,
            r = record.display()
        ),
    );

    let out = barry(dir.path())
        .args(["--model", "gpt-test", "-p", "say hi"])
        .output()
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello from codex"
    );

    let args = std::fs::read_to_string(dir.path().join("record.args")).unwrap();
    assert_eq!(args.trim(), "exec --json --sandbox read-only -m gpt-test -");
    let stdin = std::fs::read_to_string(dir.path().join("record.stdin")).unwrap();
    assert!(stdin.contains("User:\nsay hi"), "{stdin}");
    let env = std::fs::read_to_string(dir.path().join("record.env")).unwrap();
    assert!(!env.contains("OPENAI_API_KEY") && !env.contains("CODEX_ACCESS_TOKEN"));
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_provider_reports_a_failed_turn_generically() {
    let dir = tempfile::tempdir().unwrap();
    fake_codex(
        dir.path(),
        r#"cat > /dev/null
echo '{"type":"error","error":{"message":"secret detail"}}'
echo '{"type":"turn.failed","error":{"message":"secret detail"}}'
exit 1"#,
    );
    let out = barry(dir.path()).args(["-p", "hi"]).output().await.unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(!all.contains("secret detail"), "{all}");
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_provider_without_the_cli_fails_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    // PATH holds only an empty directory, so `codex` cannot be found.
    let out = barry(dir.path())
        .env("PATH", dir.path())
        .args(["-p", "hi"])
        .output()
        .await
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
