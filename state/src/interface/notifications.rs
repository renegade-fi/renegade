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

use tokio::sync::oneshot::Receiver;

use crate::{error::StateError, replication::error::ReplicationError};

/// The proposal waiter awaits a proposal's successful application to the raft
/// log
#[derive(Debug)]
pub struct ProposalWaiter {
    /// The channels on which the notifications will be sent
    recvs: Vec<Receiver<Result<(), ReplicationError>>>,
}

impl ProposalWaiter {
    /// Create a new proposal waiter
    pub fn new(recv: Receiver<Result<(), ReplicationError>>) -> Self {
        Self { recvs: vec![recv] }
    }

    /// Join two proposal waiters into one
    pub fn join(self, other: Self) -> Self {
        let recvs = self.recvs.into_iter().chain(other.recvs).collect();
        Self { recvs }
    }
}

impl Future for ProposalWaiter {
    type Output = Result<(), StateError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        for recv in self.recvs.iter_mut() {
            ready!(recv.poll_unpin(cx))
                .map_err(err_str!(StateError::Proposal))? // RecvError
                .map_err(err_str!(StateError::Proposal))?; // ReplicationError
        }

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use crate::replication::error::ReplicationError;

    use super::ProposalWaiter;

    /// Test a waiter on a single proposal
    #[tokio::test]
    async fn test_single_proposal() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let waiter = ProposalWaiter::new(rx);

        // Send an Ok
        tx.send(Ok(())).unwrap();
        assert!(waiter.await.is_ok());
    }

    /// Tests a waiter on multiple proposals
    #[tokio::test]
    async fn test_multi_proposal_ok() {
        let (tx1, rx1) = tokio::sync::oneshot::channel();
        let (tx2, rx2) = tokio::sync::oneshot::channel();
        let waiter = ProposalWaiter::new(rx1).join(ProposalWaiter::new(rx2));

        // Send two Oks
        tx1.send(Ok(())).unwrap();
        tx2.send(Ok(())).unwrap();
        assert!(waiter.await.is_ok());
    }

    /// Tests a waiter on multiple proposals in which an error is returned
    #[tokio::test]
    async fn test_multi_proposal_err() {
        let (tx1, rx1) = tokio::sync::oneshot::channel();
        let (tx2, rx2) = tokio::sync::oneshot::channel();
        let waiter = ProposalWaiter::new(rx1).join(ProposalWaiter::new(rx2));

        // Send an Ok and an Err
        tx1.send(Ok(())).unwrap();
        tx2.send(Err(ReplicationError::ProposalResponse("test".to_string()))).unwrap();
        assert!(waiter.await.is_err());
    }
}
