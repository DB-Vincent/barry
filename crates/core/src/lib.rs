//! Core agent loop for barry.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use barry_protocol::{ApprovalChoice, ApprovalRequest};

pub mod agent;
pub(crate) mod bounded;
pub mod config;
pub mod context;
pub mod hooks;
pub mod prompt;
pub mod redact;
pub mod session;
pub mod tools;
pub use agent::Agent;

/// A future returned by [`Approver::decide`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors from the core agent.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("config error: {0}")]
    Config(String),
    #[error("provider error: {0}")]
    Provider(String),
    /// A filesystem or process failure (#29). Kept apart from `Provider` so a
    /// missing file is not reported as an LLM failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
