//! Core agent loop for barry.

#![forbid(unsafe_code)]

use barry_protocol::{ApprovalChoice, ApprovalRequest};

pub mod agent;
pub mod config;
pub mod context;
pub mod hooks;
pub mod prompt;
pub mod redact;
pub mod session;
pub mod tools;
pub use agent::Agent;

/// A boxed future, as returned by [`Approver::decide`].
pub use futures::future::BoxFuture;

/// Errors from the core agent.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("config error: {0}")]
    Config(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("event channel closed")]
    ChannelClosed,
}

/// An approval decision callback.
pub trait Approver: Send + Sync {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice>;
}
