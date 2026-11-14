//! macOS sandbox using Seatbelt (`sandbox-exec`).
//!
//! Builds a `sandbox-exec` command line with a Seatbelt profile that
//! restricts file, network, and process access according to `SandboxSpec`.

use std::path::{Path, PathBuf};

use crate::SandboxError;

/// Build a `sandbox-exec` [`tokio::process::Command`] for `shell_command`.
pub(crate) fn command(
    spec: &crate::SandboxSpec,
    shell_command: &str,
) -> Result<tokio::process::Command, SandboxError> {
    let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");

    // Build the Seatbelt profile.
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec process-fork)\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow file-read*)\n\
         (allow file-write-data (literal \"/dev/null\") (literal \"/dev/tty\"))\n\
         (allow pseudo-tty)\n\
         (allow file-ioctl (literal \"/dev/tty\"))\n",
    );

    // Writable roots.
    for (i, root) in spec.writable_roots.iter().enumerate() {
        profile.push_str(&format!(
            "(allow file-write* (subpath (param \"WRITABLE_ROOT_{}\")))\n",
            i
        ));
    }

    // Protected read-only paths.
    for (i, p) in spec.protected_ro.iter().enumerate() {
        if p.exists() {
            profile.push_str(&format!(
                "(deny file-write* (subpath (param \"PROTECTED_{}\")))\n",
                i
            ));
        }
    }

    // Explicit grants are allowed *after* the protected denies so a grant
    // overrides protection for exactly the directory the user approved
    // (BC-4.5). The last matching rule wins in Seatbelt.
    for (i, g) in spec.grants.iter().enumerate() {
        if g.exists() {
            profile.push_str(&format!(
                "(allow file-write* (subpath (param \"GRANT_{}\")))\n",
                i
            ));
        }
    }

    // Read-deny paths.
    for (i, p) in spec.read_deny.iter().enumerate() {
        if p.exists() {
            profile.push_str(&format!(
                "(deny file-read* (subpath (param \"DENY_READ_{}\")))\n",
                i
            ));
        }
    }

    // Network.
    if spec.network {
        profile.push_str("(allow network*)\n");
    }

    // Pass parameters.
    for (i, root) in spec.writable_roots.iter().enumerate() {
        cmd.arg("-D")
            .arg(format!("WRITABLE_ROOT_{}={}", i, root.display()));
    }
    for (i, p) in spec.protected_ro.iter().enumerate() {
        if p.exists() {
            cmd.arg("-D")
                .arg(format!("PROTECTED_{}={}", i, p.display()));
        }
    }
    for (i, g) in spec.grants.iter().enumerate() {
        if g.exists() {
            cmd.arg("-D").arg(format!("GRANT_{}={}", i, g.display()));
        }
    }
    for (i, p) in spec.read_deny.iter().enumerate() {
        if p.exists() {
            cmd.arg("-D")
                .arg(format!("DENY_READ_{}={}", i, p.display()));
        }
    }

    cmd.arg("-p").arg(&profile);
    cmd.arg("--").arg("/bin/sh").arg("-c").arg(shell_command);

    // Run in the session cwd. bwrap does this with --chdir on Linux; on macOS
    // sandbox-exec inherits the parent's cwd, so set it explicitly.
    cmd.current_dir(&spec.cwd);

    // Strip the inherited environment, keeping only the same minimal allowlist
    // as the Linux sandbox (BC-4.4).
    cmd.env_clear();
    for (key, value) in crate::sandbox_env() {
        cmd.env(key, value);
    }

    cmd.process_group(0);

    Ok(cmd)
}

/// Not applicable on macOS (no re-exec helper needed; sandbox-exec handles
/// everything in one invocation).
pub(crate) fn run_helper_if_invoked() {
    let _ = ();
}
