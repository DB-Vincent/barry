//! Linux sandbox using bubblewrap (bwrap).
//!
//! Builds a bwrap command line that re-executes the barry binary as
//! `__sandbox-exec` inside a mount namespace. The helper installs a seccomp
//! filter then execs the requested command.
//!
//! bwrap arguments:
//!
//! ```text
//!   bwrap --ro-bind / / --dev /dev --proc /proc
//!         --bind <root> <root>           (each writable root)
//!         --ro-bind <p> <p>              (each protected_ro path that exists)
//!         --bind <grant> <grant>         (each explicit grant)
//!         --tmpfs <dir>                  (each read-deny directory that exists,
//!                                         or is missing under a writable root)
//!         --ro-bind /dev/null <file>     (each read-deny file that exists)
//!         --unshare-user --unshare-pid --unshare-ipc --cap-drop ALL
//!         [--unshare-net if !network]
//!         --die-with-parent --new-session --chdir <cwd>
//!         -- <barry_exe> __sandbox-exec -- /bin/sh -c <cmd>
//! ```

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::path::PathBuf;
use std::process::Stdio;

use crate::SandboxError;

/// Build a bwrap [`tokio::process::Command`] for `shell_command`.
///
/// Mount order matters (BC-4.5):
///   1. `--ro-bind / /` (everything read-only by default)
///   2. writable roots (cwd + extras), read-write
///   3. protected paths, read-only (must come after a writable parent so
///      `.git` stays read-only inside a writable cwd)
///   4. explicit grants, read-write (a grant overrides protection)
///   5. read-deny masks (strongest: always hidden)
pub(crate) fn command(
    spec: &crate::SandboxSpec,
    shell_command: &str,
) -> Result<tokio::process::Command, SandboxError> {
    let bwrap = which_bwrap()?;

    let mut cmd = tokio::process::Command::new(bwrap);
    cmd.arg("--ro-bind").arg("/").arg("/");
    cmd.arg("--dev").arg("/dev");
    cmd.arg("--proc").arg("/proc");

    // Writable roots first, so a protected subdirectory can be re-mounted
    // read-only afterwards.
    for root in &spec.writable_roots {
        cmd.arg("--bind").arg(root).arg(root);
    }

    // Protected paths are mounted read-only after the writable roots, so a
    // writable cwd does not silently make `.git` writable again.
    for p in &spec.protected_ro {
        if p.exists() {
            cmd.arg("--ro-bind").arg(p).arg(p);
        }
    }

    // Explicit user grants are mounted read-write last, overriding protection
    // for exactly the directory the user approved (BC-4.5).
    for grant in &spec.grants {
        if grant.exists() {
            cmd.arg("--bind").arg(grant).arg(grant);
        }
    }

    // Read-deny directories masked with tmpfs; read-deny files masked with /dev/null.
    // Applied last so a grant cannot accidentally expose a read-denied path.
    //
    // A path that does not exist yet cannot be masked unless bwrap can create
    // the mountpoint. It can only do that inside a writable mount; masking
    // elsewhere would make bwrap fail (the rest of `/` is read-only). Missing
    // entries under a writable root are masked as directories: the sandbox
    // cannot then create anything readable at that name.
    for d in &spec.read_deny {
        if d.is_dir() || (!d.exists() && mountpoint_creatable(spec, d)) {
            cmd.arg("--tmpfs").arg(d);
        }
    }
    for f in &spec.read_deny {
        if f.exists() && f.is_file() {
            cmd.arg("--ro-bind").arg("/dev/null").arg(f);
        }
    }

    // User namespace; optionally a network namespace (network = false).
    cmd.arg("--unshare-user");
    if !spec.network {
        cmd.arg("--unshare-net");
    }

    // Separate PID and IPC namespaces so the command can neither see nor signal
    // processes outside the sandbox, nor reach host shared memory and
    // semaphores. Capabilities are dropped entirely: nothing inside needs one.
    cmd.arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--cap-drop")
        .arg("ALL");

    cmd.arg("--die-with-parent")
        .arg("--new-session")
        .arg("--chdir")
        .arg(&spec.cwd);

    // Environment: clear all variables, then set only a minimal safe set.
    // This prevents secrets (API keys, tokens) from leaking into the sandbox.
    let env_cmd = build_sandbox_env(shell_command);

    // Re-exec barry as the sandbox helper, which installs seccomp and runs the command.
    let barry_exe = helper_exe()?;
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

/// Locate the barry executable to re-exec as the sandbox helper.
///
/// In a normal run this is the running binary. Test binaries are launched from
/// `target/<profile>/deps/<test>` or, depending on the cargo layout,
/// `target/<profile>/build/<crate>/<hash>/out/<test>`, so in debug builds we
/// walk up the ancestors and take the first `barry` executable found next to
/// one of them (#15).
///
/// Neither that ancestor walk nor `BARRY_BIN_OVERRIDE` applies to a release
/// build: the helper runs inside the sandbox with the user's privileges, so a
/// release binary must not be redirectable to an arbitrary executable by a
/// file sitting nearby or by an environment variable.
fn helper_exe() -> Result<PathBuf, SandboxError> {
    let override_path = if cfg!(debug_assertions) {
        std::env::var("BARRY_BIN_OVERRIDE").ok()
    } else {
        None
    };
    if let Some(path) = override_path.filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    let exe = std::env::current_exe().map_err(SandboxError::CurrentExe)?;
    if exe.file_stem().and_then(std::ffi::OsStr::to_str) == Some("barry") {
        return Ok(exe);
    }

    if cfg!(debug_assertions) {
        for ancestor in exe.ancestors().skip(1) {
            let candidate = ancestor.join("barry");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(SandboxError::HelperNotFound { exe })
}

/// Build the inner shell command that runs under `env -i` to strip secrets.
///
/// The outer `/bin/sh -c` (passed by the sandbox helper) runs this, which
/// clears the environment and sets only PATH, HOME, USER, LANG, `LC_ALL`, TERM,
/// TMPDIR before executing the user's command.
fn build_sandbox_env(shell_command: &str) -> String {
    let mut env = String::from("env -i");
    for (key, value) in crate::sandbox_env() {
        env.push(' ');
        env.push_str(&key);
        env.push('=');
        env.push_str(&shell_escape(&value));
    }
    env.push_str(" /bin/sh -c ");
    env.push_str(&shell_escape(shell_command));
    env
}

/// Wrap a string in single quotes for safe shell interpolation.
/// Any single quotes in the input are escaped by ending the quote,
/// adding an escaped quote, and starting a new quote.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Whether bwrap can create a mountpoint at `path`: its parent must exist and
/// be writable inside the sandbox, i.e. covered by a writable root or a grant.
/// Elsewhere bwrap refuses ("Read-only file system") and the command fails.
fn mountpoint_creatable(spec: &crate::SandboxSpec, path: &std::path::Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if !parent.is_dir() {
        return false;
    }
    spec.writable_roots
        .iter()
        .chain(spec.grants.iter())
        .any(|root| parent.starts_with(root))
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
///
/// ```text
/// barry __sandbox-exec -- /bin/sh -c <cmd>
/// ```
///
/// Installs a seccomp filter then runs the command. The seccomp filter is
/// inherited by the child process.
pub(crate) fn run_helper_if_invoked() {
    let args: Vec<_> = std::env::args_os().collect();
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

/// Syscalls the filter always denies, whatever their arguments.
fn denied_syscalls() -> Vec<i64> {
    vec![
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
        // Namespace and process-control escape hatches (#15): `unshare` and
        // `setns` only move between namespaces, and nothing legitimate inside
        // the sandbox needs to. `userfaultfd` and `personality` are common
        // kernel-exploit primitives.
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_userfaultfd,
        libc::SYS_personality,
    ]
}

/// `clone` rules that deny the call when its flags ask for a new namespace.
///
/// A plain denylist entry for `clone` would break every thread and process the
/// sandbox creates, so the filter looks at the flags argument (index 0) and
/// only rejects the namespace bits, one rule per bit.
///
/// `clone3` takes its flags behind a pointer and cannot be filtered this way;
/// it is left alone deliberately, because denying it outright (rather than
/// returning ENOSYS) breaks threading for the tools running inside.
fn namespace_clone_rules() -> Result<Vec<seccompiler::SeccompRule>, String> {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};

    let flags = [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ];

    flags
        .into_iter()
        .map(|flag| {
            let flag = flag as u64;
            let condition = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(|e| format!("failed to build clone condition: {e}"))?;
            SeccompRule::new(vec![condition])
                .map_err(|e| format!("failed to build clone rule: {e}"))
        })
        .collect()
}

/// Install a seccomp filter that EPERMs dangerous syscalls.
///
/// bwrap already sets `no_new_privs`, which is required for seccomp without
/// `CAP_SYS_ADMIN`.
fn install_seccomp_filter() -> Result<(), String> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for syscall in denied_syscalls() {
        rules.insert(syscall, vec![]);
    }
    rules.insert(libc::SYS_clone, namespace_clone_rules()?);

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
