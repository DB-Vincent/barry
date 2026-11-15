//! The `agent` tool stub.

use barry_protocol::{DecidedBy, Decision, ToolSpec};
use futures::future::BoxFuture;
use serde_json::json;

use super::{Tool, ToolCtx, ToolResult};
use crate::CoreError;

pub(super) struct AgentTool;

impl Tool for AgentTool {
    fn spec(&self) -> ToolSpec {
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
        }
    }

    /// Advertised (PLAN 5.1, BC-2.11) so the model can see the interface,
    /// but sub-agents arrive in M8 (PLAN 6.6). Say so plainly instead of
    /// letting it look like a typo.
    fn execute<'a>(&'a self, mut ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(async move {
            ctx.record_decision(
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
        })
    }
}
