//! Tool specs advertised to the model, and the executors behind them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy, Decision, ToolCall, ToolSpec};
use barry_sandbox::{self as sandbox, SandboxSpec};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::bounded::{read_numbered, ReadError, StreamCapture, STREAM_LIMIT};
use crate::config::Config;
use crate::hooks::{Hook, HookOutcome};
use crate::session::{decided_by_label, decision_label, EntryKind, SessionLog};
use crate::{Approver, CoreError};

/// The result of one tool call, before it becomes a [`barry_protocol::Message::Tool`].
pub(crate) struct ToolResult {
    pub(crate) ok: bool,
    pub(crate) content: String,
    pub(crate) display: String,
    /// Bash exit code, when the tool ran a command.
    pub(crate) exit_code: Option<i32>,
}

impl ToolResult {
    fn new(ok: bool, content: String, display: String) -> Self {
        Self {
            ok,
            content,
            display,
            exit_code: None,
        }
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

/// Record the decision for a call *before* the tool runs, so a crash during
/// execution still leaves an audit trail (BC-5.1). A log write failure is
/// fatal for the call: running a tool without its decision would leave a gap.
fn record_decision(
    log: &mut Option<&mut SessionLog>,
    call: &ToolCall,
    decision: &Decision,
    decided_by: &DecidedBy,
) -> Result<(), CoreError> {
    let Some(session) = log.as_mut() else {
        return Ok(());
    };
    session
        .append(EntryKind::ToolDecision {
            call_id: call.id.clone(),
            tool: call.name.clone(),
            input: call.arguments.clone(),
            decision: decision_label(decision),
            decided_by: decided_by_label(decided_by),
        })
        .map_err(|err| CoreError::Session(err.to_string()))
}

/// Record a directory grant as soon as the user approves it.
fn record_grant(log: &mut Option<&mut SessionLog>, dir: &Path) -> Result<(), CoreError> {
    let Some(session) = log.as_mut() else {
        return Ok(());
    };
    session
        .append(EntryKind::Grant {
            dir: dir.display().to_string(),
        })
        .map_err(|err| CoreError::Session(err.to_string()))
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

/// Record a bash prefix approval as soon as the user approves it.
fn record_prefix(log: &mut Option<&mut SessionLog>, prefix: &str) -> Result<(), CoreError> {
    let Some(session) = log.as_mut() else {
        return Ok(());
    };
    session
        .append(EntryKind::PrefixApproved {
            prefix: prefix.to_string(),
        })
        .map_err(|err| CoreError::Session(err.to_string()))
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
    ]
}

pub(crate) async fn execute_tool(
    call: &ToolCall,
    _cfg: &Config,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
    mut log: Option<&mut SessionLog>,
    hooks: &[Hook],
) -> Result<ToolResult, CoreError> {
    // PLAN 6.5: PreToolUse hooks run before the policy. A hook can deny or
    // block the tool, rewrite its input, or emit a warning.
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    let mut arguments = call.arguments.clone();
    for hook in hooks.iter().filter(|h| h.matches(&call.name)) {
        let input = serde_json::to_string(&arguments).unwrap_or_default();
        match hook
            .run_pre_tool_use(&call.name, &input, &cwd, "main", cancel)
            .await?
        {
            HookOutcome::Deny { reason } => {
                record_decision(
                    &mut log,
                    call,
                    &Decision::Deny {
                        reason: format!("hook denied: {reason}"),
                    },
                    &DecidedBy::Hook("pre-tool-use".to_string()),
                )?;
                return Ok(ToolResult::new(
                    false,
                    format!("hook denied: {reason}"),
                    "hook denied".to_string(),
                ));
            }
            HookOutcome::Block { reason } => {
                record_decision(
                    &mut log,
                    call,
                    &Decision::Deny {
                        reason: format!("hook blocked: {reason}"),
                    },
                    &DecidedBy::Hook("pre-tool-use".to_string()),
                )?;
                return Ok(ToolResult::new(
                    false,
                    format!("hook blocked: {reason}"),
                    "hook blocked".to_string(),
                ));
            }
            HookOutcome::UpdatedInput { input } => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&input) {
                    arguments = parsed;
                }
            }
            HookOutcome::Warning { reason } => {
                let _ = log
                    .as_mut()
                    .map(|l| l.append(EntryKind::Notice { text: reason }));
            }
            HookOutcome::Ask { reason } => {
                // PLAN 6.5: a hook may ask instead of deciding. The user
                // answers; a denial is final, an approval still faces the
                // policy check below.
                let req = ApprovalRequest {
                    id: call.id.clone(),
                    tool: call.name.clone(),
                    summary: format!("{} (asked by hook)", call.name),
                    reason: reason.clone(),
                    grant_path: None,
                };
                if approver.decide(&req).await == ApprovalChoice::Deny {
                    record_decision(
                        &mut log,
                        call,
                        &Decision::Deny {
                            reason: format!("hook asked: {reason}"),
                        },
                        &DecidedBy::User,
                    )?;
                    return Ok(ToolResult::new(
                        false,
                        format!("denied by user (hook asked: {reason})"),
                        "denied by user".to_string(),
                    ));
                }
            }
            HookOutcome::Allow => {}
        }
    }
    match call.name.as_str() {
        "read" => {
            let path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
            execute_read_with_policy(path, policy, call, &mut log).await
        }
        // `arguments`, not `call.arguments`: a PreToolUse hook may have
        // rewritten the input, and the rewrite must be what runs.
        "write" => {
            execute_write_with_approval(call, &arguments, policy, approver, cancel, &mut log).await
        }
        "edit" => {
            execute_edit_with_approval(call, &arguments, policy, approver, cancel, &mut log).await
        }
        "bash" => {
            let command = arguments
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Resolve default and bounds at the boundary; the worker takes a
            // plain u64 and needs no Option.
            let timeout_secs = arguments
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .map(|secs| secs.clamp(1, 600))
                .unwrap_or(120);

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
                        // "Once" runs this one command and records nothing:
                        // approving on demand must not silently approve every
                        // later command that starts with the same word.
                        ApprovalChoice::Once => {
                            record_decision(&mut log, call, &Decision::Allow, &DecidedBy::User)?;
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
                        ApprovalChoice::AlwaysThisSession => {
                            let prefix = session_prefix(command);
                            if let Some(prefix) = &prefix {
                                policy.approve_prefix(prefix.clone());
                                record_prefix(&mut log, &prefix.join(" "))?;
                            }
                            record_decision(&mut log, call, &Decision::Allow, &DecidedBy::User)?;
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
        // Not in the tool list until sub-agents land (M8, PLAN 6.6):
        // advertising a tool that always fails costs context on every request
        // and invites a wasted turn (#33). A call that arrives anyway (an old
        // session, a model that saw it before) gets a plain answer.
        "agent" => {
            record_decision(
                &mut log,
                call,
                &Decision::Deny {
                    reason: "sub-agents are not available yet".to_string(),
                },
                &DecidedBy::Default,
            )?;
            Ok(ToolResult::new(
                false,
                "sub-agents are not available yet: the agent tool arrives in M8".to_string(),
                "agent unavailable".to_string(),
            ))
        }
        _ => {
            record_decision(
                &mut log,
                call,
                &Decision::Deny {
                    reason: "unknown tool".to_string(),
                },
                &DecidedBy::Default,
            )?;
            Ok(ToolResult::new(
                false,
                format!("unknown tool: {}", call.name),
                format!("unknown tool: {}", call.name),
            ))
        }
    }
}

/// Read a file with line numbers, buffering a bounded head and tail instead of
/// the whole file (#19). The result already carries the PLAN 6.4 marker when
/// the file did not fit.
async fn execute_read(path: &str) -> Result<ToolResult, CoreError> {
    // The stat, the windowed read and the newline count are filesystem work on
    // a synchronous helper: keep them off the runtime thread (#25).
    let path = Path::new(path).to_path_buf();
    let read = tokio::task::spawn_blocking(move || read_numbered(&path))
        .await
        .map_err(|err| CoreError::Provider(format!("read task failed: {err}")))?;

    match read {
        Ok(numbered) => Ok(ToolResult::new(true, numbered.clone(), numbered)),
        // A file too large to read is a failed call the model can act on, not
        // an internal error: say what to do instead.
        Err(err @ ReadError::TooLarge { .. }) => {
            let message = format!("not read: {err}");
            Ok(ToolResult::new(false, message.clone(), message))
        }
        Err(ReadError::Io(err)) => Err(CoreError::Io(err)),
    }
}

/// Resolve the path a write or edit will really touch.
///
/// The policy already canonicalised the path to decide; writing to that same
/// canonical target means a symlink cannot be swapped in between the check and
/// the write to redirect the bytes elsewhere.
fn canonical_target(policy: &Option<Policy>, path: &str) -> Result<PathBuf, CoreError> {
    match policy {
        Some(policy) => barry_policy::canonicalise(policy.cwd(), Path::new(path))
            .map_err(|e| CoreError::Provider(format!("cannot resolve path: {e}"))),
        None => Ok(PathBuf::from(path)),
    }
}

/// Write `content` to `target` atomically and without following a symlink at
/// the final component.
///
/// A sibling temp file is written first and then renamed over the target:
/// `rename` replaces a symlink instead of following it, and a failed write
/// never leaves a half-written file behind.
async fn write_file(target: &Path, content: &str) -> std::io::Result<()> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let tmp = parent.join(format!(
        ".{}.barry-{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));

    tokio::fs::write(&tmp, content).await?;
    // Keep the mode of the file being replaced (an edit must not turn 0644
    // into 0600). Symlinks are not followed: `rename` below replaces the link.
    if let Ok(meta) = tokio::fs::symlink_metadata(target).await {
        if meta.is_file() {
            let _ = tokio::fs::set_permissions(&tmp, meta.permissions()).await;
        }
    }
    if let Err(err) = tokio::fs::rename(&tmp, target).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(err);
    }
    Ok(())
}

/// Run a read through the policy check before reading the file.
async fn execute_read_with_policy(
    path: &str,
    policy: &Option<Policy>,
    call: &ToolCall,
    log: &mut Option<&mut SessionLog>,
) -> Result<ToolResult, CoreError> {
    let decision = match policy {
        Some(policy) => policy.check_read(Path::new(path)),
        None => Decision::Allow,
    };
    match decision {
        Decision::Allow => {
            record_decision(log, call, &Decision::Allow, &DecidedBy::Default)?;
        }
        Decision::Deny { reason } => {
            record_decision(
                log,
                call,
                &Decision::Deny {
                    reason: reason.clone(),
                },
                &DecidedBy::Rule("read-deny".to_string()),
            )?;
            return Ok(ToolResult::new(
                false,
                format!("read denied: {reason}"),
                "read denied".to_string(),
            ));
        }
        Decision::Ask { reason } => {
            record_decision(
                log,
                call,
                &Decision::Ask {
                    reason: reason.clone(),
                },
                &DecidedBy::Default,
            )?;
            return Ok(ToolResult::new(
                false,
                format!("read requires approval: {reason}"),
                "read requires approval".to_string(),
            ));
        }
    }

    execute_read(path).await
}

async fn execute_write(path: &Path, content: &str) -> Result<ToolResult, CoreError> {
    write_file(path, content).await.map_err(CoreError::Io)?;
    Ok(ToolResult::new(
        true,
        format!("wrote {} bytes to {}", content.len(), path.display()),
        format!("wrote {} bytes to {}", content.len(), path.display()),
    ))
}

async fn execute_edit(
    path: &Path,
    old_string: &str,
    new_string: &str,
) -> Result<ToolResult, CoreError> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(CoreError::Io)?;
    let count = content.matches(old_string).count();

    match count {
        0 => Ok(ToolResult::new(
            false,
            format!(
                "no matches found for '{}' in {}",
                old_string,
                path.display()
            ),
            format!("no match to edit in {}", path.display()),
        )),
        1 => {
            let new_content = content.replacen(old_string, new_string, 1);
            write_file(path, &new_content)
                .await
                .map_err(CoreError::Io)?;
            Ok(ToolResult::new(
                true,
                format!(
                    "replaced 1 occurrence of '{}' with '{}' in {}",
                    old_string,
                    new_string,
                    path.display()
                ),
                format!("edited {}", path.display()),
            ))
        }
        n => Ok(ToolResult::new(
            false,
            format!(
                "found {} matches for '{}' in {}; no changes made",
                n,
                old_string,
                path.display()
            ),
            format!("{} matches in {}; no changes made", n, path.display()),
        )),
    }
}

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
        Decision::Allow => {
            // A path covered by an earlier grant was decided by the user, not
            // by the default in-cwd rule. Keep `decided_by` truthful after
            // "always this session".
            let decided_by = if policy.is_granted(Path::new(path)) {
                DecidedBy::User
            } else {
                DecidedBy::Default
            };
            Ok(WriteDecision {
                allowed: true,
                decision,
                decided_by,
                grant: None,
            })
        }
        Decision::Deny { .. } => Ok(WriteDecision {
            // Policy-level deny: no user prompt.
            allowed: false,
            decision,
            decided_by: DecidedBy::Default,
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
                ApprovalChoice::Once => Ok(WriteDecision {
                    allowed: true,
                    decision: Decision::Allow,
                    decided_by: DecidedBy::User,
                    grant: None,
                }),
                ApprovalChoice::AlwaysThisSession => {
                    let granted =
                        grant_path.and_then(|dir| policy.grant_dir(&dir).ok().map(|()| dir));
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

/// The result the model sees when a write or edit was refused. The policy's
/// reason is passed through: "denied by user" and "path is a dangling symlink"
/// call for very different next steps.
fn denied_result(decision: &Decision) -> ToolResult {
    let reason = match decision {
        Decision::Deny { reason } => reason.clone(),
        _ => "denied by user".to_string(),
    };
    ToolResult::new(false, reason.clone(), reason)
}

/// Run a write through the policy + approval flow.
async fn execute_write_with_approval(
    call: &ToolCall,
    arguments: &serde_json::Value,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
    log: &mut Option<&mut SessionLog>,
) -> Result<ToolResult, CoreError> {
    let path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let content = arguments
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let decision = check_write_approval(&call.id, path, "write", policy, approver, cancel).await?;
    // Record the approval before doing the write, so a crash cannot lose it.
    record_decision(log, call, &decision.decision, &decision.decided_by)?;
    if let Some(dir) = &decision.grant {
        record_grant(log, dir)?;
    }
    if decision.allowed {
        // Write through the canonical target, so what the policy approved is
        // exactly what is written even if the path is a symlink.
        let target = canonical_target(policy, path)?;
        execute_write(&target, content).await
    } else {
        Ok(denied_result(&decision.decision))
    }
}

/// Run an edit through the policy + approval flow.
async fn execute_edit_with_approval(
    call: &ToolCall,
    arguments: &serde_json::Value,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
    log: &mut Option<&mut SessionLog>,
) -> Result<ToolResult, CoreError> {
    let path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let old_string = arguments
        .get("old_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_string = arguments
        .get("new_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let decision = check_write_approval(&call.id, path, "edit", policy, approver, cancel).await?;
    record_decision(log, call, &decision.decision, &decision.decided_by)?;
    if let Some(dir) = &decision.grant {
        record_grant(log, dir)?;
    }
    if decision.allowed {
        let target = canonical_target(policy, path)?;
        execute_edit(&target, old_string, new_string).await
    } else {
        Ok(denied_result(&decision.decision))
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
