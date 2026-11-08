//! Core agent loop for barry.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use barry_llm::Provider;
use barry_protocol::{ApprovalChoice, ApprovalRequest, Event, StopReason};
use futures::channel::mpsc;
use tokio_util::sync::CancellationToken;

pub mod config;

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
}

/// An approval decision callback.
pub trait Approver: Send + Sync {
    fn decide(&self, req: &ApprovalRequest) -> BoxFuture<'_, ApprovalChoice>;
}

/// The main agent that drives the turn loop.
#[allow(dead_code)]
pub struct Agent {
    cfg: crate::config::Config,
    provider: Arc<dyn Provider>,
    approver: Arc<dyn Approver>,
}

impl Agent {
    pub fn new(
        _cfg: crate::config::Config,
        _provider: Arc<dyn Provider>,
        _approver: Arc<dyn Approver>,
    ) -> Result<Self, CoreError> {
        Err(CoreError::NotImplemented(
            "Agent::new not yet implemented".into(),
        ))
    }

    pub fn resume(
        _cfg: crate::config::Config,
        _provider: Arc<dyn Provider>,
        _approver: Arc<dyn Approver>,
        _session_file: &Path,
    ) -> Result<Self, CoreError> {
        Err(CoreError::NotImplemented(
            "Agent::resume not yet implemented".into(),
        ))
    }

    pub async fn run_turn(
        &mut self,
        _user_input: &str,
        _events: mpsc::Sender<Event>,
        _cancel: CancellationToken,
    ) -> Result<StopReason, CoreError> {
        Err(CoreError::NotImplemented(
            "Agent::run_turn not yet implemented".into(),
        ))
    }

    pub fn session_path(&self) -> &Path {
        Path::new("")
    }
}
