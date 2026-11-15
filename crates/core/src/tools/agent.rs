//! The `agent` tool: not advertised until sub-agents land.

use barry_protocol::{DecidedBy, Decision};

use super::{ToolCtx, ToolResult};
use crate::CoreError;

/// The name a stray call is dispatched on.
pub(super) const NAME: &str = "agent";

/// Not in the tool list until sub-agents land (M8, PLAN 6.6): advertising a
/// tool that always fails costs context on every request and invites a wasted
/// turn (#33). A call that arrives anyway gets a plain answer.
pub(super) fn unavailable(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
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
}
