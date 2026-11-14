/// BC-5.2 `barry log verify` on an untouched log prints `ok` and exits 0.
/// After one byte of any line is edited, it reports that line and exits 1.
use barry_core::session::{EntryKind, SessionLog};

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
