//! Defines a handle by which a consuming worker may await a state transition's
//! application
//!
//! The underlying raft node will dequeue a proposal and apply it to the state
//! machine. Only then will the notification be sent to the worker.
use common::{new_async_shared, AsyncShared};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{applicator::return_type::ApplicatorReturnType, error::StateError};

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
