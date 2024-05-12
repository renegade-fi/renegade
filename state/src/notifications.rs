//! Defines a handle by which a consuming worker may await a state transition's
//! application
//!
//! The underlying raft node will dequeue a proposal and apply it to the state
//! machine. Only then will the notification be sent to the worker.
use common::{new_async_shared, AsyncShared};
use futures::{ready, Future};
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};
use uuid::Uuid;

use crate::{applicator::return_type::ApplicatorReturnType, error::StateError};

/// Error message emitted when a proposal channel closes unexpectedly
const ERR_PROPOSAL_CLOSED: &str = "Proposal channel closed unexpectedly";

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
        if let Some(sender) = self.map.write().await.remove(&id) {
            sender.send(result).unwrap();
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
}

impl ProposalWaiter {
    /// Create a new waiter from the given channel
    pub fn new(inner: ProposalResultReceiver) -> Self {
        Self { inner }
    }
}

impl Future for ProposalWaiter {
    type Output = ProposalReturnType;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let res = ready!(Pin::new(&mut self.get_mut().inner).poll(cx))
            .map_err(|_| StateError::Proposal(ERR_PROPOSAL_CLOSED.to_string()))?;
        Poll::Ready(res)
    }
}
