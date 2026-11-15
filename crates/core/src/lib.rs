//! Core agent loop for barry.

use barry_protocol::{ApprovalChoice, ApprovalRequest, DecidedBy};

mod agent;
pub mod approval_file;
pub(crate) mod bounded;
pub mod budget;
pub mod config;
mod context;
mod hooks;
mod prompt;
mod redact;
pub mod session;
mod tools;
pub use agent::{Agent, RunStats};

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
    /// A configuration value that cannot be used.
    #[error("config error: {0}")]
    Config(String),
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
    /// A filesystem or process failure (#29). Kept apart from `Provider` so a
    /// missing file is not reported as an LLM failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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

    /// Like [`Approver::decide`], and says who decided, for the audit log.
    /// The default attributes the decision to the user. An approver driven by
    /// rules overrides this so the log shows the rule, and so the agent does
    /// not turn a one-off approval into a wider session grant.
    fn decide_attributed(
        &self,
        req: &ApprovalRequest,
    ) -> BoxFuture<'_, (ApprovalChoice, DecidedBy)> {
        let decision = self.decide(req);
        Box::pin(async move { (decision.await, DecidedBy::User) })
    }
}
