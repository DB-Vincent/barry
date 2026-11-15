//! The `bash` tool: policy check, optional OS sandbox, denial-retry.

use std::sync::Arc;
use std::time::Duration;

use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy, Decision, ToolSpec};
use barry_sandbox::{self as sandbox, SandboxSpec};
use futures::future::BoxFuture;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{record_decision, record_grant, record_prefix, Tool, ToolCtx, ToolResult};
use crate::context::truncate;
use crate::session::SessionLog;
use crate::{Approver, CoreError};

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
        .and_then(|v| v.as_u64())
        .map(|secs| secs.clamp(1, 600))
        .unwrap_or(120);
    let ToolCtx {
        call,
        policy,
        approver,
        cancel,
        mut log,
        ..
    } = ctx;

    // Policy check: deny > grant > ask > allow.
    let Some(policy) = policy.as_mut() else {
        // No policy → run unsandboxed (backstop for headless/cli
        // without policy).
        record_decision(&mut log, call, &Decision::Allow, &DecidedBy::Default)?;
        return execute_bash_none(command, timeout_secs, cancel).await;
    };
    let (decision, rule_id) = policy.check_bash(command);
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
            match approver.decide(&req).await {
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
                ApprovalChoice::Once | ApprovalChoice::AlwaysThisSession => {
                    // Grant the first word of the command as a session prefix.
                    let prefix = command.split_whitespace().next().map(str::to_string);
                    if let Some(first_word) = &prefix {
                        policy.approve_prefix(first_word);
                    }
                    record_decision(&mut log, call, &Decision::Allow, &DecidedBy::User)?;
                    if let Some(prefix) = &prefix {
                        record_prefix(&mut log, prefix)?;
                    }
                    run_sandboxed_with_retry(
                        policy,
                        command,
                        timeout_secs,
                        cancel,
                        approver,
                        call.id.clone(),
                        &mut log,
                    )
                    .await
                }
            }
        }
        Decision::Allow => {
            record_decision(&mut log, call, &Decision::Allow, &decided_by)?;
            run_sandboxed_with_retry(
                policy,
                command,
                timeout_secs,
                cancel,
                approver,
                call.id.clone(),
                &mut log,
            )
            .await
        }
    }
}

/// Sends SIGKILL to a whole process group. The child is spawned with
/// `process_group(0)`, so `-<pid>` reaches the shell and everything it started.
fn kill_process_group(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(format!("-{pid}"))
        .output();
}

/// Returns `true` if a tool result indicates the sandbox blocked the command.
/// The command failed (ok:false, exit_code != 0) and stderr contains a
/// sandbox denial message ("Operation not permitted", "Read-only file system",
/// "Permission denied", or "No such file or directory" when writing outside
/// the writable roots).
fn sandbox_denied(result: &ToolResult) -> bool {
    !result.ok
        && result.content.contains("exit_code:")
        && !result.content.starts_with("exit_code: 0")
        && (result.content.contains("Operation not permitted")
            || result.content.contains("Read-only file system")
            || result.content.contains("Permission denied")
            || result.content.contains("No such file or directory"))
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
            return path.parent().map(|p| p.to_path_buf());
        }
    }
    None
}

/// Run bash directly (no sandbox). Used when no policy is configured.
async fn execute_bash_none(
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

/// Common execution logic: spawn, race cancel vs timeout vs completion.
async fn run_bash_command(
    cmd: tokio::process::Command,
    timeout_secs: u64,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let mut cmd = cmd;
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0);

    let child = cmd
        .spawn()
        .map_err(|e| CoreError::Provider(format!("failed to run command: {e}")))?;

    let child_id = child.id().unwrap_or(0);

    let wait = async move { child.wait_with_output().await };

    tokio::select! {
        biased;
        () = cancel.cancelled() => {
            kill_process_group(child_id);
            Ok(ToolResult::interrupted())
        }
        result = tokio::time::timeout(Duration::from_secs(timeout_secs), wait) => {
            match result {
                Ok(Ok(output)) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stdout_raw = String::from_utf8_lossy(&output.stdout);
                    let stderr_raw = String::from_utf8_lossy(&output.stderr);
                    let stdout = truncate(&stdout_raw, 30_000);
                    let stderr = truncate(&stderr_raw, 30_000);

                    let content =
                        format!("exit_code: {exit_code}\nstdout: {stdout}\nstderr: {stderr}");
                    Ok(ToolResult::new(
                        exit_code == 0,
                        content,
                        format!("bash exit {exit_code}"),
                    )
                    .with_exit_code(Some(exit_code)))
                }
                Ok(Err(io_err)) => Err(CoreError::Provider(format!(
                    "failed to read command output: {io_err}"
                ))),
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
        protected_ro: policy
            .protected()
            .iter()
            .map(|p| policy.cwd().join(p))
            .filter(|p| p.exists())
            .collect(),
        network: policy.network(),
    }
}

/// Run bash inside the OS sandbox with denial-retry support.
///
/// If the sandbox blocks the command (exit_code != 0, stderr contains a
/// sandbox denial message), offer the user a directory grant and retry once
/// (PLAN 6.2, BC-4.2). If the user denies the grant, the original sandbox
/// failure goes to the model unchanged.
async fn run_sandboxed_with_retry(
    policy: &mut Policy,
    command: &str,
    timeout_secs: u64,
    cancel: &CancellationToken,
    approver: &Arc<dyn Approver>,
    call_id: String,
    log: &mut Option<&mut SessionLog>,
) -> Result<ToolResult, CoreError> {
    let first = execute_bash_sandboxed(sandbox_spec(policy), command, timeout_secs, cancel).await?;
    if !sandbox_denied(&first) {
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

    match approver.decide(&req).await {
        // Denial: the model sees the original sandbox failure, not a generic
        // "denied by user", so it can reason about the actual block.
        ApprovalChoice::Deny => Ok(first),
        ApprovalChoice::Once | ApprovalChoice::AlwaysThisSession => {
            policy
                .grant_dir(&target_dir)
                .map_err(|e| CoreError::Provider(format!("failed to grant directory: {e}")))?;
            record_grant(log, &target_dir)?;
            execute_bash_sandboxed(sandbox_spec(policy), command, timeout_secs, cancel).await
        }
    }
}
