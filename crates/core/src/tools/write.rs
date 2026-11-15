//! The `write` tool.

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::json;

use super::{run_with_write_approval, Tool, ToolCtx, ToolResult};
use crate::CoreError;

pub(super) struct WriteTool;

impl Tool for WriteTool {
    fn spec(&self) -> ToolSpec {
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
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run(ctx))
    }
}

async fn run(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let path = ctx.str_arg("path");
    let content = ctx.str_arg("content");
    run_with_write_approval(&mut ctx, "write", &path, || write_file(&path, &content)).await
}

fn write_file(path: &str, content: &str) -> Result<ToolResult, CoreError> {
    std::fs::write(path, content).map_err(|e| CoreError::Provider(e.to_string()))?;
    Ok(ToolResult::new(
        true,
        format!("wrote {} bytes to {}", content.len(), path),
        format!("wrote {} bytes to {}", content.len(), path),
    ))
}
