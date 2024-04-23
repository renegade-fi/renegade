//! Defines a handle by which a consuming worker may await a state transition's
//! application
//!
//! The underlying raft node will dequeue a proposal and apply it to the state
//! machine. Only then will the notification be sent to the worker.
use futures::{future::FutureExt, ready};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use util::err_str;

use tokio::sync::oneshot::{Receiver, Sender};

use crate::{
    applicator::return_type::ApplicatorReturnType, error::StateError,
    replication::error::ReplicationError,
};

/// The return type of the proposal waiter
pub type ProposalReturnType = Result<ApplicatorReturnType, ReplicationError>;
/// The sender of the proposal result
pub type ProposalResultSender = Sender<ProposalReturnType>;
/// The receiver of the proposal result
pub type ProposalResultReceiver = Receiver<ProposalReturnType>;

/// The proposal waiter awaits a proposal's successful application to the raft
/// log
#[derive(Debug)]
pub struct ProposalWaiter {
    /// The channel on which the notifications will be sent
    recv: ProposalResultReceiver,
}

impl ProposalWaiter {
    /// Create a new proposal waiter
    pub fn new(recv: ProposalResultReceiver) -> Self {
        Self { recv }
    }
}

impl Future for ProposalWaiter {
    type Output = Result<ApplicatorReturnType, StateError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let val = ready!(self.recv.poll_unpin(cx))
                .map_err(err_str!(StateError::Proposal))? // RecvError
                .map_err(Into::<StateError>::into); // ReplicationError
        Poll::Ready(val)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        applicator::return_type::ApplicatorReturnType, replication::error::ReplicationError,
    };

    use super::ProposalWaiter;

    /// Test a waiter on a single proposal
    #[tokio::test]
    async fn test_single_proposal() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let waiter = ProposalWaiter::new(rx);

        // Send an Ok
        tx.send(Ok(ApplicatorReturnType::None)).unwrap();
        assert!(waiter.await.is_ok());
    }

    /// Test a waiter on a single proposal that errors
    #[tokio::test]
    async fn test_single_proposal_err() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let waiter = ProposalWaiter::new(rx);

        // Send an Err
        tx.send(Err(ReplicationError::EntryNotFound)).unwrap();
        assert!(waiter.await.is_err());
    }
}
