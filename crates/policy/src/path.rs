//! Path canonicalisation for the policy engine.
//!
//! Turns a user-supplied path (relative or absolute) into a canonical,
//! symlink-resolved absolute path. `..` components are rejected, and
//! symlinks are followed during canonicalisation of existing ancestors,
//! so a symlink inside cwd that points outside counts as outside cwd
//! (PLAN 6.1.1, BC-3.5).

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Errors from path canonicalisation.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("path escapes the working directory via `..`: {path:?}")]
    DotDot { path: PathBuf },
    #[error("io error canonicalising {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Canonicalise `path` relative to `cwd`.
///
/// Walks the path component by component. While each prefix exists, it is
/// canonicalised with [`std::fs::canonicalize`], which resolves symlinks and
/// `..`. Once a component does not exist, it (and all following components)
/// are "remaining" and appended as-is. If any remaining component is `..`,
/// the path is rejected.
pub fn canonicalise(cwd: &Path, path: &Path) -> Result<PathBuf, PathError> {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    // Reject any `..` component up front: it is an escape hatch regardless
    // of whether the intermediate directory exists (PLAN 6.1.1, BC-3.5).
    for component in base.components() {
        if matches!(component, Component::ParentDir) {
            return Err(PathError::DotDot { path: base.clone() });
        }
    }

    let mut current: PathBuf = PathBuf::new();
    let mut remaining: Vec<std::ffi::OsString> = Vec::new();
    let mut found_missing = false;

    let components: Vec<_> = base.components().collect();
    for component in components.iter() {
        let next = current.join(component);

        // The root component ("/" on Linux) always "exists" as a prefix.
        if matches!(component, Component::RootDir) {
            current = next;
            continue;
        }

        if found_missing {
            remaining.push(component.as_os_str().to_os_string());
            current = next;
            continue;
        }

        if next.exists() {
            match std::fs::canonicalize(&next) {
                Ok(canonical) => current = canonical,
                Err(source) => {
                    return Err(PathError::Io { path: next, source });
                }
            }
        } else {
            found_missing = true;
            remaining.push(component.as_os_str().to_os_string());
            current = next;
        }
    }

    for comp in &remaining {
        if comp == ".." {
            return Err(PathError::DotDot { path: current });
        }
    }

    Ok(current)
}

/// Returns `true` if `canonical` is inside `root` (or equal to it).
pub fn is_under(canonical: &Path, root: &Path) -> bool {
    canonical.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_inside_cwd() {
        let cwd = std::env::temp_dir().join("barry-test-cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(cwd.join("sub")).unwrap();

        let result = canonicalise(&cwd, std::path::Path::new("sub/file.txt")).unwrap();
        assert_eq!(result, cwd.join("sub/file.txt"));
    }

    #[test]
    fn dotdot_is_rejected() {
        let cwd = std::env::temp_dir().join("barry-test-cwd2");
        std::fs::create_dir_all(&cwd).unwrap();

        let result = canonicalise(&cwd, std::path::Path::new("../x"));
        assert!(matches!(result, Err(PathError::DotDot { .. })));
    }

    #[test]
    fn symlink_outside_cwd_resolves_outside() {
        let cwd = std::env::temp_dir().join("barry-test-cwd3");
        let target = std::env::temp_dir().join("barry-test-symlink-target");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&target).unwrap();

        let link = cwd.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = canonicalise(&cwd, link.join("file.txt").as_path()).unwrap();
        assert_eq!(result, target.join("file.txt"));
        assert!(!is_under(&result, &cwd));
    }
}
