//! BC-6.2 Instructions over 32 KiB are cut and marked `[truncated]`.
#![allow(
    unsafe_code,
    reason = "Rust 2024 makes env::set_var unsafe; the tests that use it do not share the variable across threads"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use barry_core::context::instructions::instructions_section;
use std::sync::Mutex;

static HOME_LOCK: Mutex<()> = Mutex::new(());

fn with_home<F: FnOnce() -> R, R>(home: &tempfile::TempDir, f: F) -> R {
    let _guard = HOME_LOCK.lock().unwrap();
    // SAFETY: test-only; no other thread reads or writes the environment here.
    unsafe {
        std::env::set_var("HOME", home.path());
    }
    let r = f();
    // SAFETY: test-only; no other thread reads or writes the environment here.
    unsafe {
        std::env::remove_var("HOME");
    }
    r
}

fn big_content(n: usize) -> String {
    format!("x{}\n", "a".repeat(n))
}

#[test]
fn bc_6_2_instructions_over_32kib_are_truncated() {
    let home = tempfile::tempdir().unwrap();
    with_home(&home, || {
        let git_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(git_root.path().join(".git")).unwrap();
        let cwd = git_root.path().to_path_buf();

        // Global AGENTS.md that alone exceeds 32 KiB.
        std::fs::create_dir_all(home.path().join(".config/barry")).unwrap();
        std::fs::write(
            home.path().join(".config/barry/AGENTS.md"),
            big_content(40_000),
        )
        .unwrap();

        let section = instructions_section(git_root.path(), &cwd);

        // Starts with the heading and the beginning of the file.
        assert!(section.starts_with("# Project instructions"));
        assert!(section.contains("## "));
        // The overflow is marked.
        assert!(section.contains("[truncated]"));
        // It does not contain the whole 40 KiB file.
        assert!(
            section.len() < 40_000,
            "section too long: {}",
            section.len()
        );
    });
}

#[test]
fn bc_6_2_under_cap_is_not_truncated() {
    let home = tempfile::tempdir().unwrap();
    with_home(&home, || {
        let git_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(git_root.path().join(".git")).unwrap();
        let cwd = git_root.path().to_path_buf();

        std::fs::create_dir_all(home.path().join(".config/barry")).unwrap();
        std::fs::write(home.path().join(".config/barry/AGENTS.md"), "small\n").unwrap();

        let section = instructions_section(git_root.path(), &cwd);
        assert!(!section.contains("[truncated]"));
        assert!(section.contains("small"));
    });
}
