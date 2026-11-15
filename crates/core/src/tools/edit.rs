//! The `edit` tool.

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::json;

use super::{run_with_write_approval, Tool, ToolCtx, ToolResult};
use crate::CoreError;

pub(super) struct EditTool;

impl Tool for EditTool {
    fn spec(&self) -> ToolSpec {
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
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run(ctx))
    }
}

async fn run(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let path = ctx.str_arg("path");
    let old_string = ctx.str_arg("old_string");
    let new_string = ctx.str_arg("new_string");
    run_with_write_approval(&mut ctx, "edit", &path, || {
        edit_file(&path, &old_string, &new_string)
    })
    .await
}

fn edit_file(path: &str, old_string: &str, new_string: &str) -> Result<ToolResult, CoreError> {
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
