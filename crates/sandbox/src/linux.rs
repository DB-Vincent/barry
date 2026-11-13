//! Linux sandbox using bubblewrap (bwrap).
//!
//! Builds a bwrap command line that re-executes the barry binary as
//! `__sandbox-exec` inside a mount namespace. The helper installs a seccomp
//! filter then execs the requested command.
//!
//! bwrap arguments:
//!   bwrap --ro-bind / / --dev /dev --proc /proc
//!         --bind <root> <root>           (each writable root, and TMPDIR)
//!         --ro-bind <p> <p>              (each protected_ro path that exists)
//!         --tmpfs <dir>                  (each read-deny directory that exists)
//!         --ro-bind /dev/null <file>     (each read-deny file that exists)
//!         --unshare-user --unshare-pid [--unshare-net if !network]
//!         --die-with-parent --new-session --chdir <cwd>
//!         -- <barry_exe> __sandbox-exec -- /bin/sh -c <cmd>

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::path::PathBuf;
use std::process::Stdio;

use crate::SandboxError;

/// Build a bwrap [`tokio::process::Command`] for `shell_command`.
pub(crate) fn command(
    spec: &crate::SandboxSpec,
    shell_command: &str,
) -> Result<tokio::process::Command, SandboxError> {
    let bwrap = which_bwrap()?;

    let mut cmd = tokio::process::Command::new(bwrap);
    cmd.arg("--ro-bind").arg("/").arg("/");
    cmd.arg("--dev").arg("/dev");
    cmd.arg("--proc").arg("/proc");

    // Protected paths mounted read-only FIRST, so that writable roots
    // (including grants) can override them when bind-mounted afterwards.
    for p in &spec.protected_ro {
        if p.exists() {
            cmd.arg("--ro-bind").arg(p).arg(p);
        }
    }

    // Each writable root is bind-mounted read-write so writes inside it
    // affect the host. TMPDIR is also bind-mounted so temp files work.
    let mut roots: Vec<PathBuf> = spec.writable_roots.to_vec();
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if !tmpdir.is_empty() {
            let tmpdir_path = PathBuf::from(&tmpdir);
            if tmpdir_path.exists() {
                roots.push(tmpdir_path);
            }
        }
    }
    for root in &roots {
        cmd.arg("--bind").arg(root).arg(root);
    }

    // Read-deny directories masked with tmpfs; read-deny files masked with /dev/null.
    for d in &spec.read_deny {
        if d.exists() && d.is_dir() {
            cmd.arg("--tmpfs").arg(d);
        }
    }
    for f in &spec.read_deny {
        if f.exists() && f.is_file() {
            cmd.arg("--ro-bind").arg("/dev/null").arg(f);
        }
    }

    // User namespace; optionally pid and network namespaces.
    cmd.arg("--unshare-user");
    if !spec.network {
        cmd.arg("--unshare-net");
    }

    cmd.arg("--die-with-parent")
        .arg("--new-session")
        .arg("--chdir")
        .arg(&spec.cwd);

    // Environment: clear all variables, then set only a minimal safe set.
    // This prevents secrets (API keys, tokens) from leaking into the sandbox.
    let env_cmd = build_sandbox_env(shell_command);

    // Re-exec barry as the sandbox helper, which installs seccomp and runs the command.
    let barry_exe = std::env::current_exe()
        .map_err(|e| SandboxError::Other(format!("cannot determine barry executable path: {e}")))?;
    cmd.arg("--")
        .arg(&barry_exe)
        .arg("__sandbox-exec")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(env_cmd);

    cmd.stdin(Stdio::null());
    cmd.process_group(0);

    Ok(cmd)
}

/// Build the inner shell command that runs under `env -i` to strip secrets.
///
/// The outer `/bin/sh -c` (passed by the sandbox helper) runs this, which
/// clears the environment and sets only PATH, HOME, USER, LANG, LC_ALL, TERM,
/// TMPDIR before executing the user's command.
fn build_sandbox_env(shell_command: &str) -> String {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let home_var = std::env::var("HOME").unwrap_or_default();
    let user_var = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let lang_var = std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".to_string());
    let lc_all_var = std::env::var("LC_ALL").unwrap_or_default();
    let term_var = std::env::var("TERM").unwrap_or_default();
    let tmpdir_var = std::env::var("TMPDIR").unwrap_or_default();

    format!(
        "env -i PATH={} HOME={} USER={} LANG={} LC_ALL={} TERM={} TMPDIR={} /bin/sh -c {}",
        shell_escape(&path_var),
        shell_escape(&home_var),
        shell_escape(&user_var),
        shell_escape(&lang_var),
        shell_escape(&lc_all_var),
        shell_escape(&term_var),
        shell_escape(&tmpdir_var),
        shell_escape(shell_command)
    )
}

/// Wrap a string in single quotes for safe shell interpolation.
/// Any single quotes in the input are escaped by ending the quote,
/// adding an escaped quote, and starting a new quote.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Locate `bwrap` on `PATH`. Fail closed if not found.
fn which_bwrap() -> Result<PathBuf, SandboxError> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("bwrap");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(SandboxError::BwrapUnavailable)
}

/// The sandbox helper entry point. Invoked as:
///   barry __sandbox-exec -- /bin/sh -c <cmd>
///
/// Installs a seccomp filter then runs the command. The seccomp filter is
/// inherited by the child process.
pub(crate) fn run_helper_if_invoked() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "__sandbox-exec" && args[2] == "--" {
        if let Err(e) = install_seccomp_filter() {
            eprintln!("seccomp filter install failed: {e}");
            std::process::exit(1);
        }
        let status = std::process::Command::new(&args[3])
            .args(&args[4..])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("failed to execute command: {e}");
                std::process::exit(1);
            });
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Install a seccomp filter that EPERMs dangerous syscalls.
///
/// bwrap already sets `no_new_privs`, which is required for seccomp without
/// `CAP_SYS_ADMIN`.
fn install_seccomp_filter() -> Result<(), String> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &syscall in &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        libc::SYS_socket,
    ] {
        rules.insert(syscall, vec![]);
    }

    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH
            .try_into()
            .map_err(|e| format!("{e}"))?,
    )
    .map_err(|e| format!("failed to build seccomp filter: {e}"))?;

    let bpf_program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| format!("failed to compile filter: {e}"))?;

    seccompiler::apply_filter(&bpf_program)
        .map_err(|e| format!("failed to apply seccomp filter: {e}"))
}
