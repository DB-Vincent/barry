//! BC-6.1 AGENTS.md at the git root and in cwd (a subdirectory) both appear
//! in the system prompt, root first. The global one comes before both.
#![allow(
    unsafe_code,
    reason = "Rust 2024 makes env::set_var unsafe; the tests that use it do not share the variable across threads"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use barry_core::testing::instructions_section;
use std::path::PathBuf;

use crate::HOME_LOCK;

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

fn write_agents_md(root: &PathBuf, name: &str, content: &str) -> PathBuf {
    let p = root.join(name);
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(&p, content).unwrap();
    p
}

#[test]
fn bc_6_1_global_then_root_then_cwd() {
    let home = tempfile::tempdir().unwrap();
    with_home(&home, || {
        let git_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(git_root.path().join(".git")).unwrap();
        let cwd = git_root.path().join("sub").join("dir");
        std::fs::create_dir_all(&cwd).unwrap();

        // Global AGENTS.md
        write_agents_md(
            &home.path().join(".config/barry"),
            "AGENTS.md",
            "global instruction\n",
        );
        // Git root AGENTS.md
        write_agents_md(
            &git_root.path().to_path_buf(),
            "AGENTS.md",
            "root instruction\n",
        );
        // Cwd AGENTS.md
        write_agents_md(&cwd, "AGENTS.md", "cwd instruction\n");

        let section = instructions_section(git_root.path(), &cwd);

        // The global one comes first, then root, then cwd.
        let global_pos = section.find("global instruction").unwrap();
        let root_pos = section.find("root instruction").unwrap();
        let cwd_pos = section.find("cwd instruction").unwrap();
        assert!(global_pos < root_pos, "global before root: {section}");
        assert!(root_pos < cwd_pos, "root before cwd: {section}");

        // All three appear under the Project instructions heading.
        assert!(section.contains("# Project instructions"));
        assert!(section.contains("## "));
    });
}

#[test]
fn bc_6_1_no_git_root_falls_back_to_cwd() {
    let home = tempfile::tempdir().unwrap();
    with_home(&home, || {
        let cwd = tempfile::tempdir().unwrap();
        write_agents_md(&cwd.path().to_path_buf(), "AGENTS.md", "cwd only\n");
        write_agents_md(&home.path().join(".config/barry"), "AGENTS.md", "global\n");

        let section = instructions_section(cwd.path(), cwd.path());
        assert!(section.contains("cwd only"));
        assert!(section.contains("global"));
    });
}

#[test]
fn bc_6_1_missing_agends_md_is_silent() {
    let home = tempfile::tempdir().unwrap();
    with_home(&home, || {
        let git_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(git_root.path().join(".git")).unwrap();
        let cwd = git_root.path().to_path_buf();
        let section = instructions_section(git_root.path(), &cwd);
        assert_eq!(section, "");
    });
}
