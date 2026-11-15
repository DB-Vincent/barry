//! The `read` tool.

use barry_protocol::{DecidedBy, Decision, ToolSpec};
use futures::future::BoxFuture;
use serde_json::json;
use std::path::Path;

use super::{Tool, ToolCtx, ToolResult};
use crate::context::truncate;
use crate::CoreError;

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

/// Run a read through the policy check before reading the file.
async fn run(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let path = ctx.str_arg("path");
    let decision = match ctx.policy.as_ref() {
        Some(policy) => policy.check_read(Path::new(&path)),
        None => Decision::Allow,
    };
    match decision {
        Decision::Allow => {
            ctx.record_decision(&Decision::Allow, &DecidedBy::Default)?;
        }
        Decision::Deny { reason } => {
            ctx.record_decision(
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
            ctx.record_decision(
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

    read_file(&path)
}

fn read_file(path: &str) -> Result<ToolResult, CoreError> {
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
