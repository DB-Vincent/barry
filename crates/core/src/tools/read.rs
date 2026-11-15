//! The `read` tool.

use barry_protocol::{DecidedBy, Decision, ToolSpec};
use futures::future::BoxFuture;
use serde_json::json;
use std::path::Path;

use super::{Tool, ToolCtx, ToolResult};
use crate::CoreError;
use crate::bounded::{ReadError, read_numbered};

pub(super) struct ReadTool;

impl Tool for ReadTool {
    fn spec(&self) -> ToolSpec {
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
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run(ctx))
    }
}

/// Policy gate for the read-only tools: records the decision and returns a
/// denial result when the path is not readable. `None` means go ahead.
pub(super) fn read_gate(
    ctx: &mut ToolCtx<'_>,
    tool: &str,
    path: &str,
) -> Result<Option<ToolResult>, CoreError> {
    match ctx.policy.check_read(Path::new(path)) {
        Decision::Allow => {
            ctx.record_decision(&Decision::Allow, &DecidedBy::Default)?;
            Ok(None)
        }
        Decision::Deny { reason } => {
            ctx.record_decision(
                &Decision::Deny {
                    reason: reason.clone(),
                },
                &DecidedBy::Rule("read-deny".to_string()),
            )?;
            Ok(Some(ToolResult::new(
                false,
                format!("{tool} denied: {reason}"),
                format!("{tool} denied"),
            )))
        }
        Decision::Ask { reason } => {
            ctx.record_decision(
                &Decision::Ask {
                    reason: reason.clone(),
                },
                &DecidedBy::Default,
            )?;
            Ok(Some(ToolResult::new(
                false,
                format!("{tool} requires approval: {reason}"),
                format!("{tool} requires approval"),
            )))
        }
        // Decision is non-exhaustive: fail closed on a variant this code does
        // not know.
        _ => {
            ctx.record_decision(
                &Decision::Deny {
                    reason: "unknown policy decision".to_string(),
                },
                &DecidedBy::Default,
            )?;
            Ok(Some(ToolResult::new(
                false,
                format!("{tool} denied: unknown policy decision"),
                format!("{tool} denied"),
            )))
        }
    }
}

/// Run a read through the policy check before reading the file.
async fn run(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let path = ctx.str_arg("path");
    if let Some(denied) = read_gate(&mut ctx, "read", &path)? {
        return Ok(denied);
    }
    read_file(&path).await
}

/// Read a file with line numbers, buffering a bounded head and tail instead of
/// the whole file (#19). The result already carries the PLAN 6.4 marker when
/// the file did not fit.
async fn read_file(path: &str) -> Result<ToolResult, CoreError> {
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
