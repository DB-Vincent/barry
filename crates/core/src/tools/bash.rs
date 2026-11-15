//! The `bash` tool: policy check, optional OS sandbox, denial-retry.

use std::time::Duration;

use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy, Decision, ToolSpec};
use barry_sandbox::{self as sandbox, SandboxSpec};
use futures::future::BoxFuture;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use super::{Tool, ToolCtx, ToolResult, record_decision, record_grant, record_prefix};
use crate::CoreError;
use crate::bounded::{STREAM_LIMIT, StreamCapture};
use crate::session::SessionLog;

pub(super) struct BashTool;

impl Tool for BashTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "bash".to_string(),
            description: "Run a bash command".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to run"
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600,
                        "description": "Timeout in seconds (default 120)"
                    }
                },
                "required": ["command"]
            }),
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run(ctx))
    }
}

async fn run(ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let command = ctx.str_arg("command");
    let command = command.as_str();
    // Resolve default and bounds at the boundary; the worker takes a
    // plain u64 and needs no Option.
    let timeout_secs = ctx
        .arguments
        .get("timeout_secs")
        .and_then(serde_json::Value::as_u64)
        .map_or(120, |secs| secs.clamp(1, 600));
    let ToolCtx {
        call,
        policy,
        unsandboxed,
        approver,
        cancel,
        mut log,
        ..
    } = ctx;
    let mut run_ctx = RunCtx {
        policy,
        unsandboxed,
        approver,
        cancel,
    };

    // Policy check: deny > grant > ask > allow. The policy decides even when
    // the OS sandbox is off (#30): dropping the sandbox must not also drop the
    // deny rules and approvals.
    let (decision, rule_id) = run_ctx.policy.check_bash(command);
    let decided_by = match rule_id.as_deref() {
        // A session prefix grant is a user decision, not a rule id.
        Some(grant) if grant.starts_with("grant: ") => DecidedBy::User,
        Some(id) => DecidedBy::Rule(id.to_string()),
        None => DecidedBy::Default,
    };
    match decision {
        Decision::Deny { reason } => {
            record_decision(
                &mut log,
                call,
                &Decision::Deny {
                    reason: reason.clone(),
                },
                &decided_by,
            )?;
            Ok(ToolResult::new(
                false,
                format!("bash denied: {reason}"),
                "bash denied".to_string(),
            ))
        }
        Decision::Ask { reason } => {
            let req = ApprovalRequest {
                id: call.id.clone(),
                tool: "bash".to_string(),
                summary: format!("bash: {command}"),
                reason: reason.clone(),
                grant_path: None,
            };
            match run_ctx.approver.decide(&req).await {
                ApprovalChoice::Deny => {
                    record_decision(
                        &mut log,
                        call,
                        &Decision::Deny {
                            reason: "denied by user".to_string(),
                        },
                        &DecidedBy::User,
                    )?;
                    Ok(ToolResult::new(
                        false,
                        "denied by user".to_string(),
                        "denied by user".to_string(),
                    ))
                }
                // "Once" runs this one command and records nothing:
                // approving on demand must not silently approve every
                // later command that starts with the same word.
                ApprovalChoice::Once => {
                    record_decision(&mut log, call, &Decision::Allow, &DecidedBy::User)?;
                    run_bash(
                        &mut run_ctx,
                        command,
                        timeout_secs,
                        call.id.clone(),
                        &mut log,
                    )
                    .await
                }
                ApprovalChoice::AlwaysThisSession => {
                    let prefix = session_prefix(command);
                    if let Some(prefix) = &prefix {
                        run_ctx.policy.approve_prefix(prefix.clone());
                        record_prefix(&mut log, &prefix.join(" "))?;
                    }
                    record_decision(&mut log, call, &Decision::Allow, &DecidedBy::User)?;
                    run_bash(
                        &mut run_ctx,
                        command,
                        timeout_secs,
                        call.id.clone(),
                        &mut log,
                    )
                    .await
                }
            }
        }
        Decision::Allow => {
            record_decision(&mut log, call, &Decision::Allow, &decided_by)?;
            run_bash(
                &mut run_ctx,
                command,
                timeout_secs,
                call.id.clone(),
                &mut log,
            )
            .await
        }
        // Decision is non-exhaustive: fail closed on a variant this code does
        // not know.
        _ => {
            record_decision(
                &mut log,
                call,
                &Decision::Deny {
                    reason: "unknown policy decision".to_string(),
                },
                &decided_by,
            )?;
            Ok(ToolResult::new(
                false,
                "bash denied: unknown policy decision".to_string(),
                "bash denied".to_string(),
            ))
        }
    }
}

/// The parts of the call context that running a command needs.
struct RunCtx<'a> {
    policy: &'a mut Policy,
    unsandboxed: bool,
    approver: &'a std::sync::Arc<dyn crate::Approver>,
    cancel: &'a CancellationToken,
}

/// The argv prefix "always this session" grants for a command: the first two
/// tokens, or the first when there is only one (PLAN 6.1.3).
fn session_prefix(command: &str) -> Option<Vec<String>> {
    let prefix: Vec<String> = command
        .split_whitespace()
        .take(2)
        .map(str::to_string)
        .collect();
    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

/// Sends SIGKILL to a whole process group. The child is spawned with
/// `process_group(0)`, so `-<pid>` reaches the shell and everything it started.
fn kill_process_group(pid: u32) {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    // The group may already be gone; nothing useful to do on failure.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
}

/// Returns `true` if a tool result indicates the sandbox blocked the command.
///
/// The command must have failed (ok:false, non-zero exit) with a message only
/// the sandbox produces: "Operation not permitted" for a seccomp denial,
/// "Read-only file system" or "Permission denied" for a mount denial.
///
/// "No such file or directory" is deliberately not one of those. A plain
/// `cat missing.txt` prints exactly that, and treating it as a denial asked the
/// user to grant a directory because of a typo (#20). It counts only when the
/// command writes and its redirect target names a directory, which is how a
/// write outside the writable roots fails.
fn sandbox_denied(result: &ToolResult, command: &str) -> bool {
    if result.ok
        || !result.content.contains("exit_code:")
        || result.content.starts_with("exit_code: 0")
    {
        return false;
    }

    if result.content.contains("Operation not permitted")
        || result.content.contains("Read-only file system")
        || result.content.contains("Permission denied")
    {
        return true;
    }

    result.content.contains("No such file or directory")
        && sandbox_denied_dir(result, command).is_some()
}

/// Extracts the directory path that the sandbox denied access to.
/// Looks for a shell redirect target (`>`, `>>`, `2>`) in the command and
/// returns its parent directory, e.g. `echo x > ../outside/f` → `../outside`.
fn sandbox_denied_dir(_result: &ToolResult, command: &str) -> Option<std::path::PathBuf> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    for (i, raw) in parts.iter().enumerate() {
        let part = *raw;
        let target = if let Some(rest) = part.strip_prefix(">>") {
            if rest.is_empty() {
                parts.get(i + 1).copied()
            } else {
                Some(rest)
            }
        } else if let Some(rest) = part.strip_prefix("2>") {
            if rest.is_empty() {
                parts.get(i + 1).copied()
            } else {
                Some(rest)
            }
        } else if let Some(rest) = part.strip_prefix('>') {
            if rest.is_empty() {
                parts.get(i + 1).copied()
            } else {
                Some(rest)
            }
        } else {
            None
        };

        if let Some(target) = target {
            let path = std::path::Path::new(target);
            return path.parent().map(std::path::Path::to_path_buf);
        }
    }
    None
}

/// Run bash directly, without the OS sandbox (#30).
///
/// Only reachable when the config says `sandbox.unsandboxed = true`, which the
/// session log records at startup. Never a fallback for a missing policy or
/// for a sandbox that failed to start: those fail closed.
async fn run_bash_direct(
    command: &str,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.arg("-c").arg(command);
    run_bash_command(cmd, timeout_secs, cancel).await
}

/// Run bash inside the OS sandbox.
async fn execute_bash_sandboxed(
    spec: SandboxSpec,
    command: &str,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let cmd = sandbox::command(&spec, command)
        .map_err(|e| CoreError::Provider(format!("sandbox error: {e}")))?;
    run_bash_command(cmd, timeout_secs, cancel).await
}

/// Read one pipe into `capture`, killing the process group once the stream
/// has produced more than the capture limit (#19).
///
/// Nothing past the limit would ever reach the model, so draining the rest can
/// only cost time and memory.
async fn drain_bounded<R>(
    reader: &mut R,
    capture: &mut StreamCapture,
    pid: u32,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        if !capture.push(&chunk[..read]) {
            kill_process_group(pid);
            return Ok(());
        }
    }
}

/// Common execution logic: spawn, race cancel vs timeout vs completion.
///
/// Both pipes are drained as the command writes, so memory stays bounded no
/// matter how much it prints (#19).
async fn run_bash_command(
    cmd: tokio::process::Command,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let mut cmd = cmd;
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0);

    let mut child = cmd.spawn().map_err(CoreError::Io)?;

    let child_id = child.id().unwrap_or(0);

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CoreError::Provider("no stdout pipe".to_string()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CoreError::Provider("no stderr pipe".to_string()))?;

    let mut out_capture = StreamCapture::new(STREAM_LIMIT);
    let mut err_capture = StreamCapture::new(STREAM_LIMIT);

    // Both pipes must be read concurrently: a command that fills the pipe it
    // is not being read from would block until the timeout.
    let wait = async move {
        let (out_result, err_result) = tokio::join!(
            drain_bounded(&mut stdout, &mut out_capture, child_id),
            drain_bounded(&mut stderr, &mut err_capture, child_id),
        );
        let status = child.wait().await?;
        out_result?;
        err_result?;
        Ok::<_, std::io::Error>((status, out_capture, err_capture))
    };

    tokio::select! {
        biased;
        () = cancel.cancelled() => {
            kill_process_group(child_id);
            Ok(ToolResult::interrupted())
        }
        result = tokio::time::timeout(Duration::from_secs(timeout_secs), wait) => {
            match result {
                Ok(Ok((status, out_capture, err_capture))) => {
                    let exit_code = status.code().unwrap_or(-1);
                    let out_limited = out_capture.limited();
                    let err_limited = err_capture.limited();
                    let mut stdout_text = out_capture.into_text();
                    let mut stderr_text = err_capture.into_text();
                    if out_limited || err_limited {
                        let note = format!(
                            "\n[... output over {STREAM_LIMIT} bytes; command killed ...]"
                        );
                        if out_limited {
                            stdout_text.push_str(&note);
                        }
                        if err_limited {
                            stderr_text.push_str(&note);
                        }
                    }

                    let content =
                        format!("exit_code: {exit_code}\nstdout: {stdout_text}\nstderr: {stderr_text}");
                    Ok(ToolResult::new(
                        exit_code == 0,
                        content,
                        format!("bash exit {exit_code}"),
                    )
                    .with_exit_code(Some(exit_code)))
                }
                Ok(Err(io_err)) => Err(CoreError::Io(io_err)),
                Err(_elapsed) => {
                    kill_process_group(child_id);
                    Ok(ToolResult::new(
                        false,
                        format!("timed out after {timeout_secs}s"),
                        format!("bash timed out after {timeout_secs}s"),
                    ))
                }
            }
        }
    }
}

/// Build the sandbox spec from the current policy. Rebuilt after a grant so
/// the retry sees the newly granted directory.
fn sandbox_spec(policy: &Policy) -> SandboxSpec {
    SandboxSpec {
        cwd: policy.cwd().to_path_buf(),
        writable_roots: policy.writable_roots().to_vec(),
        grants: policy.grants().to_vec(),
        read_deny: policy.read_deny_paths().to_vec(),
        // Every protected path under every writable root, including nested
        // repositories. Computed by the policy, not `cwd.join(p)` here, so an
        // extra writable root or a submodule is protected too.
        protected_ro: policy.protected_paths().to_vec(),
        network: policy.network(),
    }
}

/// Run bash inside the OS sandbox with denial-retry support.
///
/// If the sandbox blocks the command (`exit_code != 0`, stderr contains a
/// sandbox denial message), offer the user a directory grant and retry once
/// (PLAN 6.2, BC-4.2). If the user denies the grant, the original sandbox
/// failure goes to the model unchanged.
async fn run_bash(
    ctx: &mut RunCtx<'_>,
    command: &str,
    timeout_secs: u64,
    call_id: String,
    log: &mut Option<&mut SessionLog>,
) -> Result<ToolResult, CoreError> {
    if ctx.unsandboxed {
        return run_bash_direct(command, timeout_secs, ctx.cancel).await;
    }

    let first =
        execute_bash_sandboxed(sandbox_spec(ctx.policy), command, timeout_secs, ctx.cancel).await?;
    if !sandbox_denied(&first, command) {
        return Ok(first);
    }

    // Only offer a grant when we can name the directory the sandbox refused.
    let Some(target_dir) = sandbox_denied_dir(&first, command) else {
        return Ok(first);
    };

    let req = ApprovalRequest {
        id: call_id,
        tool: "bash".to_string(),
        summary: format!("bash: {command}"),
        reason: "sandbox blocked the command".to_string(),
        grant_path: Some(target_dir.clone()),
    };

    match ctx.approver.decide(&req).await {
        // Denial: the model sees the original sandbox failure, not a generic
        // "denied by user", so it can reason about the actual block.
        ApprovalChoice::Deny => Ok(first),
        ApprovalChoice::Once | ApprovalChoice::AlwaysThisSession => {
            ctx.policy
                .grant_dir(&target_dir)
                .map_err(|e| CoreError::Provider(format!("failed to grant directory: {e}")))?;
            record_grant(log, &target_dir)?;
            execute_bash_sandboxed(sandbox_spec(ctx.policy), command, timeout_secs, ctx.cancel)
                .await
        }
    }
}
