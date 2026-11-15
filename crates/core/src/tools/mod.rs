//! Tool specs advertised to the model, and the executors behind them.
//!
//! Each tool lives in its own module behind the [`Tool`] trait. The shared
//! wrapping (PreToolUse hooks, unknown-tool handling, decision logging) lives
//! here in [`execute_tool`]; each tool owns its policy check, because the
//! checks differ per tool (read-deny, write approval, bash allowlist).

mod agent;
mod bash;
mod edit;
mod read;
mod write;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use barry_policy::Policy;
use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy, Decision, ToolCall, ToolSpec};
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

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

/// Everything a tool needs to run one call.
pub(crate) struct ToolCtx<'a> {
    pub(crate) call: &'a ToolCall,
    /// The call arguments after PreToolUse hooks ran (a hook may rewrite them).
    pub(crate) arguments: serde_json::Value,
    pub(crate) policy: &'a mut Option<Policy>,
    pub(crate) approver: &'a Arc<dyn Approver>,
    pub(crate) cancel: &'a CancellationToken,
    pub(crate) log: Option<&'a mut SessionLog>,
}

impl ToolCtx<'_> {
    /// A string argument, or `""` when missing or not a string.
    pub(crate) fn str_arg(&self, key: &str) -> String {
        self.arguments
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// Record the decision for the call (see [`record_decision`]).
    pub(crate) fn record_decision(
        &mut self,
        decision: &Decision,
        decided_by: &DecidedBy,
    ) -> Result<(), CoreError> {
        record_decision(&mut self.log, self.call, decision, decided_by)
    }
}

/// Record the decision for a call *before* the tool runs, so a crash during
/// execution still leaves an audit trail (BC-5.1). A log write failure is
/// fatal for the call: running a tool without its decision would leave a gap.
pub(crate) fn record_decision(
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
pub(crate) fn record_grant(log: &mut Option<&mut SessionLog>, dir: &Path) -> Result<(), CoreError> {
    let Some(session) = log.as_mut() else {
        return Ok(());
    };
    session
        .append(EntryKind::Grant {
            dir: dir.display().to_string(),
        })
        .map_err(|err| CoreError::Session(err.to_string()))
}

/// Record a bash prefix approval as soon as the user approves it.
pub(crate) fn record_prefix(
    log: &mut Option<&mut SessionLog>,
    prefix: &str,
) -> Result<(), CoreError> {
    let Some(session) = log.as_mut() else {
        return Ok(());
    };
    session
        .append(EntryKind::PrefixApproved {
            prefix: prefix.to_string(),
        })
        .map_err(|err| CoreError::Session(err.to_string()))
}

/// One tool the model can call.
pub(crate) trait Tool: Send + Sync {
    /// The spec advertised to the model. `spec().name` is the dispatch key.
    fn spec(&self) -> ToolSpec;

    /// Run the call: policy check, decision logging, then the work itself.
    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>>;
}

/// All tools, in the order they are advertised to the model.
fn registry() -> &'static [Box<dyn Tool>] {
    static REGISTRY: OnceLock<Vec<Box<dyn Tool>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        vec![
            Box::new(read::ReadTool),
            Box::new(write::WriteTool),
            Box::new(edit::EditTool),
            Box::new(bash::BashTool),
            Box::new(agent::AgentTool),
        ]
    })
}

pub(crate) fn tool_specs() -> Vec<ToolSpec> {
    registry().iter().map(|tool| tool.spec()).collect()
}

pub(crate) async fn execute_tool(
    call: &ToolCall,
    _cfg: &Config,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
    cancel: &CancellationToken,
    log: Option<&mut SessionLog>,
    hooks: &[Hook],
) -> Result<ToolResult, CoreError> {
    let mut ctx = ToolCtx {
        call,
        arguments: call.arguments.clone(),
        policy,
        approver,
        cancel,
        log,
    };
    if let Some(result) = run_pre_tool_use_hooks(&mut ctx, hooks).await? {
        return Ok(result);
    }
    match registry().iter().find(|t| t.spec().name == call.name) {
        Some(tool) => tool.execute(ctx).await,
        None => {
            ctx.record_decision(
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

/// PLAN 6.5: PreToolUse hooks run before the policy. A hook can deny or
/// block the tool, rewrite its input, or emit a warning. Returns a result
/// when a hook ended the call.
async fn run_pre_tool_use_hooks(
    ctx: &mut ToolCtx<'_>,
    hooks: &[Hook],
) -> Result<Option<ToolResult>, CoreError> {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    let name = ctx.call.name.clone();
    for hook in hooks.iter().filter(|h| h.matches(&name)) {
        let input = serde_json::to_string(&ctx.arguments).unwrap_or_default();
        match hook
            .run_pre_tool_use(&name, &input, &cwd, "main", ctx.cancel)
            .await?
        {
            HookOutcome::Deny { reason } => {
                ctx.record_decision(
                    &Decision::Deny {
                        reason: format!("hook denied: {reason}"),
                    },
                    &DecidedBy::Hook("pre-tool-use".to_string()),
                )?;
                return Ok(Some(ToolResult::new(
                    false,
                    format!("hook denied: {reason}"),
                    "hook denied".to_string(),
                )));
            }
            HookOutcome::Block { reason } => {
                ctx.record_decision(
                    &Decision::Deny {
                        reason: format!("hook blocked: {reason}"),
                    },
                    &DecidedBy::Hook("pre-tool-use".to_string()),
                )?;
                return Ok(Some(ToolResult::new(
                    false,
                    format!("hook blocked: {reason}"),
                    "hook blocked".to_string(),
                )));
            }
            HookOutcome::UpdatedInput { input } => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&input) {
                    ctx.arguments = parsed;
                }
            }
            HookOutcome::Warning { reason } => {
                let _ = ctx
                    .log
                    .as_mut()
                    .map(|l| l.append(EntryKind::Notice { text: reason }));
            }
            HookOutcome::Allow | HookOutcome::Ask { .. } => {}
        }
    }
    Ok(None)
}

/// The outcome of the write/edit approval flow.
pub(crate) struct WriteDecision {
    pub(crate) allowed: bool,
    pub(crate) decision: Decision,
    pub(crate) decided_by: DecidedBy,
    /// The directory granted by the user, if one was recorded.
    pub(crate) grant: Option<PathBuf>,
}

/// Policy + approval flow shared by the tools that modify files.
pub(crate) async fn check_write_approval(
    call_id: &str,
    path: &str,
    tool: &str,
    policy: &mut Option<Policy>,
    approver: &Arc<dyn Approver>,
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

/// Run a file-modifying tool through the policy + approval flow, record the
/// decision (and any grant) before the work, then run `work` when allowed.
pub(crate) async fn run_with_write_approval(
    ctx: &mut ToolCtx<'_>,
    tool: &str,
    path: &str,
    work: impl FnOnce() -> Result<ToolResult, CoreError>,
) -> Result<ToolResult, CoreError> {
    let decision = check_write_approval(&ctx.call.id, path, tool, ctx.policy, ctx.approver).await?;
    // Record the approval before doing the work, so a crash cannot lose it.
    ctx.record_decision(&decision.decision, &decision.decided_by)?;
    if let Some(dir) = &decision.grant {
        record_grant(&mut ctx.log, dir)?;
    }
    if decision.allowed {
        work()
    } else {
        Ok(ToolResult::new(
            false,
            "denied by user".to_string(),
            "denied by user".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_names_are_unique_and_ordered() {
        let names: Vec<String> = tool_specs().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["read", "write", "edit", "bash", "agent"]);
    }

    #[test]
    fn every_spec_is_an_object_schema_with_required_fields() {
        for spec in tool_specs() {
            assert_eq!(spec.parameters["type"], "object", "{}", spec.name);
            assert!(spec.parameters["required"].is_array(), "{}", spec.name);
        }
    }
}
