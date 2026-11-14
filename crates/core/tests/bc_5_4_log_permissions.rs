//! BC-5.4 Log files have mode 0600 and their directory 0700.
#![cfg(unix)]

use barry_core::session::SessionLog;
use std::os::unix::fs::PermissionsExt;

#[test]
fn bc_5_4_session_log_permissions() {
    let root = tempfile::tempdir().expect("tempdir");
    let sessions = root.path().join("sessions");

    let log = SessionLog::create_in(&sessions, "main").expect("create session log");
    let path = log.path().to_path_buf();

    let dir_mode = std::fs::metadata(&sessions)
        .expect("sessions dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "sessions directory is 0700");

    let file_mode = std::fs::metadata(&path)
        .expect("session file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "session file is 0600");
}

/// BC-5.4-adjacent: a second writer cannot interleave appends and break the
/// chain.
#[test]
fn bc_5_4_second_writer_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    let log = SessionLog::create_in(root.path(), "main").expect("create session log");

    let err = SessionLog::open_append(log.path())
        .err()
        .expect("a second writer is refused");
    assert!(
        err.to_string().contains("already open"),
        "the error explains the lock: {err}"
    );
}
