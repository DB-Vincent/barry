//! Core agent loop for barry.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use barry_protocol::{ApprovalChoice, ApprovalRequest};

mod agent;
pub mod config;
mod context;
mod hooks;
mod prompt;
mod redact;
pub mod session;
mod tools;
pub use agent::Agent;

/// Internals re-exported for this crate's integration tests only. Not part of
/// the supported API and may change without notice.
#[doc(hidden)]
pub mod testing {
    pub use crate::context::{instructions_section, skills_section};
    pub use crate::prompt::today;
    pub use crate::redact::Redactor;
}

/// A future returned by [`Approver::decide`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
