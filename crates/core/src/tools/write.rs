//! The `write` tool.

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::json;

use std::path::Path;

use super::{authorise_write, Tool, ToolCtx, ToolResult};
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
    match authorise_write(&mut ctx, "write", &path).await? {
        Ok(target) => {
            write_file(&target, &content).await.map_err(CoreError::Io)?;
            Ok(ToolResult::new(
                true,
                format!("wrote {} bytes to {}", content.len(), target.display()),
                format!("wrote {} bytes to {}", content.len(), target.display()),
            ))
        }
        Err(denied) => Ok(denied),
    }
}

/// Write `content` to `target` atomically and without following a symlink at
/// the final component.
///
/// A sibling temp file is written first and then renamed over the target:
/// `rename` replaces a symlink instead of following it, and a failed write
/// never leaves a half-written file behind.
pub(super) async fn write_file(target: &Path, content: &str) -> std::io::Result<()> {
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
