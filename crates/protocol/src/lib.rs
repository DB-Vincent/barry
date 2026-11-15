//! Core types for the barry agent harness.
//! Types only — no logic, no I/O.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The role of a message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// A tool call requested by the model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// A message in the conversation history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: Option<String>,
        reasoning: Option<String>,
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        tool_call_id: String,
        content: String,
        ok: bool,
    },
}

/// A tool specification presented to the model (JSON Schema parameters).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StopReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Aborted,
    Error(String),
}

/// Token usage for a request/response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// The policy decision for a tool or command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Ask { reason: String },
    Deny { reason: String },
}

/// Who made the decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DecidedBy {
    Rule(String),
    User,
    Hook(String),
    Default,
}

/// The user's answer to an approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalChoice {
    Once,
    AlwaysThisSession,
    Deny,
}

/// A request for user approval before running a tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: String,
    pub summary: String,
    pub reason: String,
    pub grant_path: Option<PathBuf>,
}

/// Events emitted by the core agent loop to the front end.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Event {
    TurnStarted,
    TextDelta(String),
    ReasoningDelta(String),
    ToolStarted {
        id: String,
        name: String,
        display: String,
    },
    ToolFinished {
        id: String,
        ok: bool,
        display: String,
    },
    ApprovalNeeded(ApprovalRequest),
    Notice(String),
    TurnFinished {
        stop: StopReason,
        usage: Option<Usage>,
    },
}
