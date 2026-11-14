//! Tool specs advertised to the model, and the executors behind them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy, Decision, ToolCall, ToolSpec};
use barry_sandbox::{self as sandbox, SandboxSpec};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::context::truncate;
use crate::{Approver, CoreError};

/// The result of one tool call, before it becomes a [`barry_protocol::Message::Tool`].
pub(crate) struct ToolResult {
    pub(crate) ok: bool,
    pub(crate) content: String,
    pub(crate) display: String,
    /// The policy decision that allowed, denied or asked about this call.
    pub(crate) decision: Decision,
    /// Who made that decision (rule, user, hook or default).
    pub(crate) decided_by: DecidedBy,
    /// Bash exit code, when the tool ran a command.
    pub(crate) exit_code: Option<i32>,
    /// A directory granted during this call, if any (BC-5.1).
    pub(crate) grant: Option<PathBuf>,
    /// A bash prefix approved during this call, if any.
    pub(crate) prefix: Option<String>,
}

impl ToolResult {
    fn new(ok: bool, content: String, display: String) -> Self {
        Self {
            ok,
            content,
            display,
            decision: Decision::Allow,
            decided_by: DecidedBy::Default,
            exit_code: None,
            grant: None,
            prefix: None,
        }
    }

    fn with_decision(mut self, decision: Decision, decided_by: DecidedBy) -> Self {
        self.decision = decision;
        self.decided_by = decided_by;
        self
    }

    fn with_exit_code(mut self, exit_code: Option<i32>) -> Self {
        self.exit_code = exit_code;
        self
    }

    /// The result recorded for a call that was cut short by cancellation.
    pub(crate) fn interrupted() -> Self {
        Self::new(
            false,
            "interrupted by user".to_string(),
            "interrupted by user".to_string(),
        )
        .with_decision(
            Decision::Deny {
                reason: "interrupted by user".to_string(),
            },
            DecidedBy::User,
        )
    }

    /// Turns a tool error into a result for the model. PLAN 5: panics and
    /// errors inside a tool never abort the turn, they become ok:false.
    pub(crate) fn internal_error(err: &CoreError) -> Self {
        Self::new(
            false,
            format!("internal tool error: {err}"),
            "internal tool error".to_string(),
        )
    }
}

pub(crate) fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "read".to_string(),
            description: "Read a file and return its contents with line numbers".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" }
                },
                "required": ["path"]
            }),
        },
        ToolSpec {
            name: "write".to_string(),
            description: "Write content to a file".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" },
                    "content": { "type": "string", "description": "Content to write" }
                },
                "required": ["path", "content"]
            }),
        },
        ToolSpec {
            name: "edit".to_string(),
            description: "Replace old_string with new_string in a file".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" },
                    "old_string": { "type": "string", "description": "Text to replace" },
                    "new_string": { "type": "string", "description": "Replacement text" }
                },
                "required": ["path", "old_string", "new_string"]
            }),
        },
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
        },
        ToolSpec {
            name: "agent".to_string(),
            description: "Run a sub-agent on a task and return its final answer".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "The task for the sub-agent"
                    },
                    "allow_writes": {
                        "type": "boolean",
                        "description": "Allow the sub-agent to write files (default false)"
                    }
                },
                "required": ["task"]
            }),
        },
    ]
}

pub(crate) async fn execute_tool(
    call: &ToolCall,
    _cfg: &Config,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    match call.name.as_str() {
        "read" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_read_with_policy(path, policy).await
        }
        "write" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = call
                .arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_write_with_approval(&call.id, path, content, policy, approver, cancel).await
        }
        "edit" => {
            let path = call
                .arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let old_string = call
                .arguments
                .get("old_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_string = call
                .arguments
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            execute_edit_with_approval(
                &call.id, path, old_string, new_string, policy, approver, cancel,
            )
            .await
        }
        "bash" => {
            let command = call
                .arguments
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Resolve default and bounds at the boundary; the worker takes a
            // plain u64 and needs no Option.
            let timeout_secs = call
                .arguments
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .map(|secs| secs.clamp(1, 600))
                .unwrap_or(120);

            // Policy check: deny > grant > ask > allow.
            let Some(policy) = policy.as_mut() else {
                // No policy → run unsandboxed (backstop for headless/cli
                // without policy).
                return execute_bash_none(command, timeout_secs, cancel).await;
            };
            let (decision, rule_id) = policy.check_bash(command);
            let decided_by = rule_id
                .clone()
                .map(DecidedBy::Rule)
                .unwrap_or(DecidedBy::Default);
            match decision {
                Decision::Deny { reason } => Ok(ToolResult::new(
                    false,
                    format!("bash denied: {reason}"),
                    "bash denied".to_string(),
                )
                .with_decision(Decision::Deny { reason }, decided_by)),
                Decision::Ask { reason } => {
                    let req = ApprovalRequest {
                        id: call.id.clone(),
                        tool: "bash".to_string(),
                        summary: format!("bash: {command}"),
                        reason,
                        grant_path: None,
                    };
                    match approver.decide(&req).await {
                        ApprovalChoice::Deny => Ok(ToolResult::new(
                            false,
                            "denied by user".to_string(),
                            "denied by user".to_string(),
                        )
                        .with_decision(
                            Decision::Deny {
                                reason: "denied by user".to_string(),
                            },
                            DecidedBy::User,
                        )),
                        ApprovalChoice::Once | ApprovalChoice::AlwaysThisSession => {
                            // Grant the first word of the command as a session prefix.
                            let prefix = command.split_whitespace().next().map(str::to_string);
                            if let Some(first_word) = &prefix {
                                policy.approve_prefix(first_word);
                            }
                            let mut result = run_sandboxed_with_retry(
                                policy,
                                command,
                                timeout_secs,
                                cancel,
                                approver,
                                call.id.clone(),
                            )
                            .await?;
                            result.decision = Decision::Allow;
                            result.decided_by = DecidedBy::User;
                            result.prefix = prefix;
                            Ok(result)
                        }
                    }
                }
                Decision::Allow => {
                    let mut result = run_sandboxed_with_retry(
                        policy,
                        command,
                        timeout_secs,
                        cancel,
                        approver,
                        call.id.clone(),
                    )
                    .await?;
                    result.decision = Decision::Allow;
                    result.decided_by = decided_by;
                    Ok(result)
                }
            }
        }
        // Advertised (PLAN 5.1, BC-2.11) so the model can see the interface,
        // but sub-agents arrive in M8 (PLAN 6.6). Say so plainly instead of
        // letting it look like a typo.
        "agent" => Ok(ToolResult::new(
            false,
            "sub-agents are not available yet: the agent tool arrives in M8".to_string(),
            "agent unavailable".to_string(),
        )
        .with_decision(
            Decision::Deny {
                reason: "sub-agents are not available yet".to_string(),
            },
            DecidedBy::Default,
        )),
        _ => Ok(ToolResult::new(
            false,
            format!("unknown tool: {}", call.name),
            format!("unknown tool: {}", call.name),
        )
        .with_decision(
            Decision::Deny {
                reason: "unknown tool".to_string(),
            },
            DecidedBy::Default,
        )),
    }
}

async fn execute_read(path: &str) -> Result<ToolResult, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
    let numbered: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| format!("{}: {}", i + 1, line))
        .collect::<Vec<_>>()
        .join("\n");

    let numbered = truncate(&numbered, 30_000).into_owned();

    Ok(ToolResult::new(true, numbered.clone(), numbered))
}

/// Run a read through the policy check before reading the file.
async fn execute_read_with_policy(
    path: &str,
    policy: &Option<Policy>,
) -> Result<ToolResult, CoreError> {
    // No policy configured → no restrictions.
    if let Some(policy) = policy {
        match policy.check_read(Path::new(path)) {
            Decision::Allow => {}
            Decision::Deny { reason } => {
                return Ok(ToolResult::new(
                    false,
                    format!("read denied: {reason}"),
                    "read denied".to_string(),
                )
                .with_decision(
                    Decision::Deny { reason },
                    DecidedBy::Rule("read-deny".to_string()),
                ));
            }
            Decision::Ask { reason } => {
                return Ok(ToolResult::new(
                    false,
                    format!("read requires approval: {reason}"),
                    "read requires approval".to_string(),
                )
                .with_decision(Decision::Ask { reason }, DecidedBy::Default));
            }
        }
    }

    execute_read(path).await
}

async fn execute_write(path: &str, content: &str) -> Result<ToolResult, CoreError> {
    std::fs::write(path, content).map_err(|e| CoreError::Provider(e.to_string()))?;
    Ok(ToolResult::new(
        true,
        format!("wrote {} bytes to {}", content.len(), path),
        format!("wrote {} bytes to {}", content.len(), path),
    ))
}

async fn execute_edit(
    path: &str,
    old_string: &str,
    new_string: &str,
) -> Result<ToolResult, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::Provider(e.to_string()))?;
    let count = content.matches(old_string).count();

    match count {
        0 => Ok(ToolResult::new(
            false,
            format!("no matches found for '{}' in {}", old_string, path),
            format!("no matches found for '{}'", old_string),
        )),
        1 => {
            let new_content = content.replacen(old_string, new_string, 1);
            std::fs::write(path, &new_content).map_err(|e| CoreError::Provider(e.to_string()))?;
            Ok(ToolResult::new(
                true,
                format!(
                    "replaced 1 occurrence of '{}' with '{}' in {}",
                    old_string, new_string, path
                ),
                format!("replaced '{}' with '{}'", old_string, new_string),
            ))
        }
        n => Ok(ToolResult::new(
            false,
            format!(
                "found {} matches for '{}' in {}; no changes made",
                n, old_string, path
            ),
            format!("found {} matches for '{}'; no changes made", n, old_string),
        )),
    }
}

/// Check whether a write to `path` is allowed by policy and user approval.
///
/// Returns `Ok(true)` if the write may proceed, `Ok(false)` if it was denied.
/// On denial, the caller should produce an ok:false result telling the model
/// the write was denied by the user.
/// The outcome of the write/edit approval flow.
struct WriteDecision {
    allowed: bool,
    decision: Decision,
    decided_by: DecidedBy,
    /// The directory granted by the user, if one was recorded.
    grant: Option<PathBuf>,
}

async fn check_write_approval(
    call_id: &str,
    path: &str,
    tool: &str,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    _cancel: &CancellationToken,
) -> Result<WriteDecision, CoreError> {
    // No policy configured → no restrictions.
    let Some(policy) = policy.as_mut() else {
        return Ok(WriteDecision {
            allowed: true,
            decision: Decision::Allow,
            decided_by: DecidedBy::Default,
            grant: None,
        });
    };

    let (decision, grant_dir) = policy.check_write(Path::new(path));
    match decision {
        Decision::Allow => Ok(WriteDecision {
            allowed: true,
            decision,
            decided_by: DecidedBy::Default,
            grant: None,
        }),
        Decision::Deny { .. } => Ok(WriteDecision {
            // Policy-level deny: no user prompt.
            allowed: false,
            decision,
            decided_by: DecidedBy::Rule("write-deny".to_string()),
            grant: None,
        }),
        Decision::Ask { reason } => {
            let grant_path = grant_dir.clone();
            let req = ApprovalRequest {
                id: call_id.to_string(),
                tool: tool.to_string(),
                summary: format!("{tool} to {path}"),
                reason,
                grant_path: grant_dir,
            };
            let choice = approver.decide(&req).await;
            match choice {
                ApprovalChoice::Deny => Ok(WriteDecision {
                    allowed: false,
                    decision: Decision::Deny {
                        reason: "denied by user".to_string(),
                    },
                    decided_by: DecidedBy::User,
                    grant: None,
                }),
                ApprovalChoice::Once | ApprovalChoice::AlwaysThisSession => {
                    let mut granted = None;
                    if let Some(dir) = grant_path {
                        if policy.grant_dir(&dir).is_ok() {
                            granted = Some(dir);
                        }
                    }
                    Ok(WriteDecision {
                        allowed: true,
                        decision: Decision::Allow,
                        decided_by: DecidedBy::User,
                        grant: granted,
                    })
                }
            }
        }
    }
}

/// Run a write through the policy + approval flow.
async fn execute_write_with_approval(
    call_id: &str,
    path: &str,
    content: &str,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    _cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let decision = check_write_approval(call_id, path, "write", policy, approver, _cancel).await?;
    if decision.allowed {
        let mut result = execute_write(path, content).await?;
        result.decision = decision.decision;
        result.decided_by = decision.decided_by;
        result.grant = decision.grant;
        Ok(result)
    } else {
        Ok(ToolResult::new(
            false,
            "denied by user".to_string(),
            "denied by user".to_string(),
        )
        .with_decision(decision.decision, decision.decided_by))
    }
}

/// Run an edit through the policy + approval flow.
async fn execute_edit_with_approval(
    call_id: &str,
    path: &str,
    old_string: &str,
    new_string: &str,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    _cancel: &CancellationToken,
) -> Result<ToolResult, CoreError> {
    let decision = check_write_approval(call_id, path, "edit", policy, approver, _cancel).await?;
    if decision.allowed {
        let mut result = execute_edit(path, old_string, new_string).await?;
        result.decision = decision.decision;
        result.decided_by = decision.decided_by;
        result.grant = decision.grant;
        Ok(result)
    } else {
        Ok(ToolResult::new(
            false,
            "denied by user".to_string(),
            "denied by user".to_string(),
        )
        .with_decision(decision.decision, decision.decided_by))
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
            let mut result =
                execute_bash_sandboxed(sandbox_spec(policy), command, timeout_secs, cancel).await?;
            result.decision = Decision::Allow;
            result.decided_by = DecidedBy::User;
            result.grant = Some(target_dir);
            Ok(result)
        }
    }
}
