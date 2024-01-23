//! Defines a handle by which a consuming worker may await a state transition's
//! application
//!
//! The underlying raft node will dequeue a proposal and apply it to the state
//! machine. Only then will the notification be sent to the worker.
use futures::future::FutureExt;
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
    /// The channel on which the notification will be sent
    recv: Receiver<Result<(), ReplicationError>>,
}

impl ProposalWaiter {
    /// Create a new proposal waiter
    pub fn new(recv: Receiver<Result<(), ReplicationError>>) -> Self {
        Self { recv }
    }
}

impl Future for ProposalWaiter {
    type Output = Result<(), StateError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.recv
            .poll_unpin(cx)
            .map_err(err_str!(StateError::Proposal))? // RecvError
            .map_err(err_str!(StateError::Proposal)) // ReplicationError
    }
}
