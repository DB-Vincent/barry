//! AGENTS.md collection for the system prompt (PLAN 6.3).
//!
//! Files are collected in this order:
//!   1. `~/.config/barry/AGENTS.md` (global)
//!   2. `AGENTS.md` in each directory from the git root down to cwd, root first
//!
//! They are joined under `# Project instructions` as `## <relative path>`
//! sections. The total is capped at 32 KiB; on overflow the last file is cut
//! and `[truncated]` is added.

use std::path::{Path, PathBuf};

/// The byte cap for the joined instructions section (PLAN 6.3).
const INSTRUCTION_CAP: usize = 32 * 1024;

/// The heading that introduces the joined AGENTS.md sections.
const HEADING: &str = "# Project instructions";

/// Build the instructions section for the system prompt.
///
/// `git_root` is the nearest ancestor of `cwd` containing `.git`, or `cwd`
/// itself if there is none. `cwd` is the current working directory.
#[must_use]
pub fn instructions_section(git_root: &Path, cwd: &Path) -> String {
    let mut files: Vec<(PathBuf, String)> = Vec::new();

    // 1. Global config AGENTS.md.
    if let Ok(home) = std::env::var("HOME") {
        let global = PathBuf::from(home).join(".config/barry/AGENTS.md");
        if let Ok(content) = std::fs::read_to_string(&global) {
            files.push((PathBuf::from("~/.config/barry/AGENTS.md"), content));
        }
    }

    // 2. AGENTS.md from git root down to cwd, root first.
    let Ok(rel) = cwd.strip_prefix(git_root) else {
        // cwd is not under the git root: only check cwd itself.
        if let Ok(content) = std::fs::read_to_string(cwd.join("AGENTS.md")) {
            files.push((PathBuf::from("AGENTS.md"), content));
        }
        return render(files);
    };

    // Walk each directory prefix from git_root down to cwd, root first.
    let mut path = git_root.to_path_buf();
    let mut check = |path: &Path| {
        let candidate = path.join("AGENTS.md");
        if let Ok(content) = std::fs::read_to_string(&candidate) {
            let label = path
                .strip_prefix(git_root)
                .map_or_else(|_| "AGENTS.md".to_string(), |p| p.display().to_string());
            let label = if label.is_empty() {
                "AGENTS.md".to_string()
            } else {
                format!("{label}/AGENTS.md")
            };
            files.push((PathBuf::from(label), content));
        }
    };
    check(&path);
    for component in rel.components() {
        path = path.join(component);
        check(&path);
    }

    render(files)
}

/// Render the collected files into the section string, applying the byte cap.
fn render(files: Vec<(PathBuf, String)>) -> String {
    if files.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(HEADING);
    out.push('\n');

    let mut used = out.len();
    for (label, content) in files {
        let header = format!("## {}\n", label.display());
        let entry = format!("{header}{content}\n");
        if used + entry.len() > INSTRUCTION_CAP {
            let remaining = INSTRUCTION_CAP.saturating_sub(used);
            // 12 = len("\n[truncated]\n")
            if remaining > header.len() + 12 {
                out.push_str(&header);
                out.push_str("\n[truncated]\n");
            } else if remaining > 12 {
                out.push_str(&header[..remaining - 12]);
                out.push_str("\n[truncated]\n");
            } else {
                out.push_str("[truncated]\n");
            }
            break;
        }
        out.push_str(&entry);
        used += entry.len();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_when_no_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        assert_eq!(instructions_section(root.path(), root.path()), "");
    }
}
