//! macOS sandbox using Seatbelt (`sandbox-exec`).
//!
//! Builds a `sandbox-exec` command line with a Seatbelt profile that
//! restricts file, network, and process access according to `SandboxSpec`.

use std::fmt::Write as _;

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
    for i in 0..spec.writable_roots.len() {
        let _ = writeln!(
            profile,
            "(allow file-write* (subpath (param \"WRITABLE_ROOT_{i}\")))"
        );
    }

    // Protected read-only paths. Skip a protected deny when the user granted
    // that path (or a parent), so a grant reliably overrides protection
    // regardless of how Seatbelt resolves equal-specificity rules (BC-4.5).
    // Seatbelt rules are path-based, so a path that does not exist yet is
    // still protected if it appears later (issue #16).
    for (i, p) in spec.protected_ro.iter().enumerate() {
        if !spec.grants.iter().any(|g| p.starts_with(g)) {
            let _ = writeln!(
                profile,
                "(deny file-write* (subpath (param \"PROTECTED_{i}\")))"
            );
        }
    }

    // Explicit grants are allowed after the protected denies. This also covers
    // a grant that is a subdirectory of a protected path, and a grant outside
    // every writable root (BC-4.2, BC-4.5).
    for (i, g) in spec.grants.iter().enumerate() {
        if g.exists() {
            let _ = writeln!(
                profile,
                "(allow file-write* (subpath (param \"GRANT_{i}\")))"
            );
        }
    }

    // Read-deny paths. Seatbelt resolves a path filter when the profile is
    // compiled, so a read-deny entry that does not exist yet matches nothing
    // here; on Linux the same path is masked by a tmpfs mount, which is what
    // makes a directory created later stay inside the sandbox (#16). Writes
    // are denied too, so an entry that does exist is neither readable nor
    // writable from a sandboxed command.
    for i in 0..spec.read_deny.len() {
        let _ = write!(
            profile,
            "(deny file-read* (subpath (param \"DENY_READ_{i}\")))\n\
             (deny file-write* (subpath (param \"DENY_READ_{i}\")))\n"
        );
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
        if !spec.grants.iter().any(|g| p.starts_with(g)) {
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
        cmd.arg("-D")
            .arg(format!("DENY_READ_{}={}", i, p.display()));
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
