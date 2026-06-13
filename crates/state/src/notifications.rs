//! Defines a handle by which a consuming worker may await a state transition's
//! application
//!
//! The underlying raft node will dequeue a proposal and apply it to the state
//! machine. Only then will the notification be sent to the worker.
use futures::Future;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Sleep, sleep};
use util::concurrency::{AsyncShared, new_async_shared};
use uuid::Uuid;

use crate::{applicator::return_type::ApplicatorReturnType, error::StateError};

/// Error message emitted when a proposal channel closes unexpectedly
const ERR_PROPOSAL_CLOSED: &str = "Proposal channel closed unexpectedly";
/// Error message emitted when a proposal is not applied within the deadline
const ERR_PROPOSAL_TIMEOUT: &str = "Proposal was not applied within the timeout";
/// The maximum time to wait for a proposal to be applied before failing the
/// caller. A proposal that never applies (e.g. a write that never commits) must
/// surface as a bounded, retryable error rather than parking the caller's task
/// forever; accumulated, such parked tasks starve the api-server runtime and
/// wedge port 3000.
///
/// Sized above the 30s that the serial apply loop can fall behind under a write
/// burst (quoter boot rebalance + concurrent client setup): at 30s, slow-but-
/// progressing proposals failed and the callers retried, and the retries piled
/// MORE proposals onto the same serial apply path — a self-reinforcing timeout
/// storm that prevented the book/orders from ever landing. 60s lets a queued
/// proposal drain before the caller gives up, breaking that feedback loop.
/// Genuinely-stuck writes are still bounded separately by the write-tx begin cap
/// (`MAX_BEGIN_TIMEOUT_RETRIES`, ~90s fail-fast-restart in storage/db.rs), so a
/// longer waiter here does not reintroduce the runtime-wedge it guards against.
const PROPOSAL_WAITER_TIMEOUT: Duration = Duration::from_secs(60);

/// The id of a proposal
pub type ProposalId = Uuid;
/// The return type of the proposal waiter
pub type ProposalReturnType = Result<ApplicatorReturnType, StateError>;
/// The sender of the proposal result
pub type ProposalResultSender = tokio::sync::oneshot::Sender<ProposalReturnType>;
/// The receiver of the proposal result
pub type ProposalResultReceiver = tokio::sync::oneshot::Receiver<ProposalReturnType>;
/// Create a new channel for a proposal result
pub fn new_proposal_result_channel() -> (ProposalResultSender, ProposalResultReceiver) {
    tokio::sync::oneshot::channel()
}

/// An index of notification channels on the open proposals
#[derive(Clone)]
pub struct OpenNotifications {
    /// The underlying map
    map: AsyncShared<HashMap<ProposalId, ProposalResultSender>>,
}

impl Default for OpenNotifications {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenNotifications {
    /// Create a new index
    pub fn new() -> Self {
        Self { map: new_async_shared(HashMap::new()) }
    }

    /// Notify a listener that a proposal has been applied
    pub async fn notify(&self, id: ProposalId, result: ProposalReturnType) {
        if let Some(sender) = self.map.write().await.remove(&id)
            && !sender.is_closed()
        {
            let _ = sender.send(result);
        }
    }

    /// Add a waiter for the given proposal, returns the channel to wait on
    pub async fn register_notification(&self, id: ProposalId) -> ProposalResultReceiver {
        let (sender, receiver) = new_proposal_result_channel();
        self.map.write().await.insert(id, sender);
        receiver
    }
}

/// A wrapper around a proposal receiver that gives a more convenient async
/// interface without channel like semantics
pub struct ProposalWaiter {
    /// The inner channel
    inner: ProposalResultReceiver,
    /// A deadline after which the waiter resolves to an error instead of
    /// parking the caller's task indefinitely
    deadline: Pin<Box<Sleep>>,
}

impl ProposalWaiter {
    /// Create a new waiter from the given channel
    pub fn new(inner: ProposalResultReceiver) -> Self {
        Self { inner, deadline: Box::pin(sleep(PROPOSAL_WAITER_TIMEOUT)) }
    }

    /// Create a waiter that is already resolved to the given result, for an
    /// operation that short-circuits without enqueueing a proposal (e.g. an
    /// idempotent create whose target already exists). Resolves immediately on
    /// the first poll, so the caller never touches the raft apply path.
    pub fn resolved(result: ProposalReturnType) -> Self {
        let (tx, rx) = new_proposal_result_channel();
        let _ = tx.send(result);
        Self::new(rx)
    }
}

impl Future for ProposalWaiter {
    type Output = ProposalReturnType;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Resolve as soon as the proposal is applied...
        if let Poll::Ready(res) = Pin::new(&mut this.inner).poll(cx) {
            let res = res.map_err(|_| StateError::Proposal(ERR_PROPOSAL_CLOSED.to_string()))?;
            return Poll::Ready(res);
        }

        // ...but never park forever: a proposal that is never applied resolves to
        // a bounded, retryable error instead of hanging the caller's task.
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(StateError::Proposal(ERR_PROPOSAL_TIMEOUT.to_string())));
        }
        Poll::Pending
    }
}
