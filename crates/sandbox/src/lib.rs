//! OS sandbox for barry.
//!
//! Runs bash commands inside an OS sandbox so that even if the policy layer
//! allows a command (or the user grants it), the sandbox can still block it.
//! Two layers: policy (software rules) + sandbox (OS enforcement).
//!
//! On Linux, commands run under `bwrap`. The barry binary re-executes itself
//! as `barry __sandbox-exec -- /bin/sh -c <cmd>` inside the bwrap mount
//! namespace, with a seccomp filter installed by the helper.
//! On macOS, commands run under `/usr/bin/sandbox-exec` with a Seatbelt profile.
//!
//! If `bwrap` is missing on Linux, commands fail closed: they never run
//! unsandboxed.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Errors from the sandbox.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("bubblewrap (bwrap) not found; install it to run commands")]
    BwrapUnavailable,
    #[error("sandbox error: {0}")]
    Other(String),
}

/// Specification for a sandboxed command execution.
#[derive(Clone)]
pub struct SandboxSpec {
    /// Session working directory.
    pub cwd: PathBuf,
    /// Directories the command may write to (bind-mounted read-write).
    pub writable_roots: Vec<PathBuf>,
    /// Directories/files the command may not read (masked or made inaccessible).
    pub read_deny: Vec<PathBuf>,
    /// Paths mounted read-only (e.g. <root>/.git).
    pub protected_ro: Vec<PathBuf>,
    /// Whether network access is allowed.
    pub network: bool,
}

/// Build a [`tokio::process::Command`] that runs `shell_command` inside the
/// sandbox described by `spec`.
///
/// On Linux this assembles a `bwrap` invocation that re-executes the barry
/// binary as `__sandbox-exec`. On macOS it assembles a `sandbox-exec`
/// invocation.
pub fn command(
    spec: &SandboxSpec,
    shell_command: &str,
) -> Result<tokio::process::Command, SandboxError> {
    #[cfg(target_os = "linux")]
    return linux::command(spec, shell_command);
    #[cfg(target_os = "macos")]
    return macos::command(spec, shell_command);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (spec, shell_command);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(SandboxError::Other(
        "sandbox not supported on this platform".into(),
    ));
}

/// Called first thing in `cli main()`. If the binary was invoked as
/// `barry __sandbox-exec -- ...` (the re-exec target inside bwrap on Linux),
/// installs the seccomp filter and execs the requested command, never
/// returning.
///
/// If not invoked as the sandbox helper, returns normally so main continues.
pub fn run_helper_if_invoked() {
    #[cfg(target_os = "linux")]
    linux::run_helper_if_invoked();
    #[cfg(not(target_os = "linux"))]
    let _ = ();
}
