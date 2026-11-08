//! Core types for the barry agent harness.
//! Types only — no logic, no I/O.

use serde::{Deserialize, Serialize};

/// The policy decision for a tool or command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Ask { reason: String },
    Deny { reason: String },
}
