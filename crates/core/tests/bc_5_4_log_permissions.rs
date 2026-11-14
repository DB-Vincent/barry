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
