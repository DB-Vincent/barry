//! Workspace test fixture.
//! Creates a tempdir with project/ (cwd, git init, README.md), outside/, home/.

use std::path::{Path, PathBuf};

pub struct Workspace {
    _tempdir: tempfile::TempDir,
    project: PathBuf,
    outside: PathBuf,
    home: PathBuf,
}

#[allow(clippy::new_without_default)]
impl Workspace {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().to_path_buf();
        let project = root.join("project");
        let outside = root.join("outside");
        let home = root.join("home");

        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let _ = std::process::Command::new("git")
            .args(["init"])
            .current_dir(&project)
            .output();
        std::fs::write(project.join("README.md"), "# Test Project\n").unwrap();

        let ssh_dir = home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_test"), "FAKE-PRIVATE-KEY").unwrap();

        let config_dir = home.join(".config").join("barry");
        std::fs::create_dir_all(&config_dir).unwrap();

        Self {
            _tempdir: tempdir,
            project,
            outside,
            home,
        }
    }

    pub fn cwd(&self) -> &Path {
        self.project.as_path()
    }

    pub fn outside(&self) -> &Path {
        self.outside.as_path()
    }

    pub fn home(&self) -> &Path {
        self.home.as_path()
    }

    pub fn file(&self, rel: &str) -> PathBuf {
        self.project.join(rel)
    }

    pub fn config(&self, toml_str: &str) {
        let config_dir = self.home.join(".config").join("barry");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), toml_str).unwrap();
    }
}
