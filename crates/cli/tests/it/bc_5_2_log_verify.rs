/// BC-5.2 `barry log verify` on an untouched log prints `ok` and exits 0.
/// After one byte of any line is edited, it reports that line and exits 1.
use barry_core::session::{EntryKind, SessionLog};
use barry_testkit::{FakeLlm, Reply};

fn verify(path: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("barry").expect("barry binary");
    cmd.args(["log", "verify"]).arg(path);
    cmd
}

#[test]
fn bc_5_2_verify_untouched_log_is_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    log.append(EntryKind::Notice {
        text: "first".to_string(),
    })
    .expect("append");
    log.append(EntryKind::Notice {
        text: "second".to_string(),
    })
    .expect("append");
    let path = log.path().to_path_buf();
    drop(log);

    verify(&path)
        .assert()
        .success()
        .stdout(predicates::str::contains("ok"));
}

#[test]
fn bc_5_2_verify_names_the_edited_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = SessionLog::create_in(dir.path(), "main").expect("create session log");
    log.append(EntryKind::Notice {
        text: "first".to_string(),
    })
    .expect("append");
    log.append(EntryKind::Notice {
        text: "second".to_string(),
    })
    .expect("append");
    let path = log.path().to_path_buf();
    drop(log);

    // Edit exactly one byte of the second line, keeping its length: change
    // "second" to "seconD". The log must name line 2.
    let content = std::fs::read_to_string(&path).expect("read log");
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    assert_eq!(lines.len(), 2, "two entries were written");
    let tampered = lines[1].replacen("second", "seconD", 1);
    assert_ne!(tampered, lines[1], "the edit actually changed line 2");
    lines[1] = tampered;
    std::fs::write(&path, lines.join("\n") + "\n").expect("write tampered log");

    verify(&path)
        .assert()
        .code(1)
        .stdout(predicates::str::contains("broken at line 2"));
}

/// BC-5.2 A log written by a real headless session verifies end to end.
#[tokio::test(flavor = "multi_thread")]
async fn bc_5_2_headless_session_log_verifies() {
    let state = tempfile::tempdir().expect("state dir");
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "hi".to_string(),
    }])
    .await;

    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .args(["-p", "hi"])
        .env_remove("BARRY_CONFIG")
        .env("XDG_STATE_HOME", state.path())
        .env("BARRY_BASE_URL", llm.uri())
        .output()
        .await
        .expect("barry runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sessions = state.path().join("barry").join("sessions");
    let path = std::fs::read_dir(&sessions)
        .expect("sessions directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("a session log was written");

    verify(&path)
        .assert()
        .success()
        .stdout(predicates::str::contains("ok ("));
}
