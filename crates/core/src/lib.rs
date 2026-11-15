//! Core agent loop for barry.

use barry_protocol::{ApprovalChoice, ApprovalRequest};

mod agent;
pub(crate) mod bounded;
pub mod budget;
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

/// A boxed future, as returned by [`Approver::decide`].
pub use futures::future::BoxFuture;

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
