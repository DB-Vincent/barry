//! The `edit` tool.

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::json;

use std::path::Path;

use super::write::write_file;
use super::{Tool, ToolCtx, ToolResult, authorise_write};
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
    match authorise_write(&mut ctx, "edit", &path).await? {
        Ok(target) => edit_file(&target, &old_string, &new_string).await,
        Err(denied) => Ok(denied),
    }
}

async fn edit_file(
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
