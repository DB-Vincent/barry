//! Core agent loop for barry.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

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

/// A future returned by [`Approver::decide`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors from the core agent.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A hook matcher is not a valid regular expression.
    #[error("invalid hook matcher {matcher:?}: {source}")]
    HookMatcher {
        matcher: String,
        #[source]
        source: regex::Error,
    },
    /// The hook input could not be serialised to JSON.
    #[error("failed to serialize hook input: {0}")]
    HookInput(#[source] serde_json::Error),
    /// The hook command could not be started.
    #[error("failed to spawn hook: {0}")]
    HookSpawn(#[source] std::io::Error),
    /// The LLM provider failed.
    #[error("provider error: {0}")]
    Llm(#[from] barry_llm::LlmError),
    /// The provider failed in a way that has no typed cause.
    #[error("provider error: {0}")]
    Provider(String),
    /// The OS sandbox could not be set up.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] barry_sandbox::SandboxError),
    /// A directory grant was rejected by the policy.
    #[error("failed to grant directory: {0}")]
    Policy(#[from] barry_policy::PolicyError),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    /// The session log failed.
    #[error("session error: {0}")]
    Session(#[from] session::SessionError),
    /// The session log to resume fails hash-chain verification.
    #[error("session error: session log is broken at line {line}")]
    SessionBroken { line: usize },
    #[error("event channel closed")]
    ChannelClosed,
}

/// An approval decision callback.
pub trait Approver: Send + Sync {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice>;
}
