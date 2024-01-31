//! The network abstraction of the replication layer; defines the interface for
//! sending and receiving raft messages from cluster peers

use crate::replication::error::ReplicationError;
use crossbeam::channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use gossip_api::request_response::raft::RaftMessage;
use raft::prelude::Message as RawRaftMessage;

/// The type used for queuing raft messages inbound from the network
pub type RaftMessageQueue = CrossbeamSender<RaftMessage>;
/// The receiver end of the raft message queue inbound from the network
pub type RaftMessageReceiver = CrossbeamReceiver<RaftMessage>;

// -----------
// | Network |
// -----------

/// The central trait that must be implemented by any networking layer used
/// by the replication layer
pub trait RaftNetwork {
    /// The error type emitted by the network implementation
    type Error: Into<ReplicationError>;

    /// Send a raft message to a peer
    ///
    /// This method MAY NOT not block
    fn send(&mut self, message: RawRaftMessage) -> Result<(), Self::Error>;

    /// Receive a raft message from the network
    ///
    /// This method MAY block
    fn recv(&mut self) -> Result<Option<RawRaftMessage>, Self::Error>;

    /// Attempt to receive a raft message from the network
    ///
    /// This method MAY NOT block
    fn try_recv(&mut self) -> Result<Option<RawRaftMessage>, Self::Error>;
}

#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    //! Test helpers for the network abstraction
    use crossbeam::channel::{
        unbounded, Receiver as CrossbeamReceiver, Sender as CrossbeamSender, TryRecvError,
    };
    use raft::prelude::Message as RaftMessage;
    use std::io::{Error as IOError, ErrorKind};

    use crate::replication::error::ReplicationError;

    use super::RaftNetwork;

    /// A mock network that is brokered by `N` channels
    ///
    /// Emulates a mesh network by sitting centralized between all
    /// point-to-point comms
    pub struct MockNetwork {
        /// The sender channel
        senders: Vec<CrossbeamSender<RaftMessage>>,
        /// The owner's receiver channel                                    
        receiver: CrossbeamReceiver<RaftMessage>,
    }

    impl MockNetwork {
        /// Constructor, returns a handle to the network mesh for each node
        pub fn new_n_way_mesh(n_nodes: usize) -> Vec<Self> {
            let mut senders = Vec::with_capacity(n_nodes);
            let mut receivers = Vec::with_capacity(n_nodes);

            for _ in 0..n_nodes {
                let (s, r) = unbounded();
                senders.push(s);
                receivers.push(r);
            }

            receivers.into_iter().map(|r| Self { senders: senders.clone(), receiver: r }).collect()
        }

        /// Create a double sided mock connection
        #[allow(dead_code)]
        pub fn new_duplex_conn() -> (Self, Self) {
            let mut res = Self::new_n_way_mesh(2 /* n_nodes */);
            (res.remove(0), res.remove(0))
        }
    }

    impl RaftNetwork for MockNetwork {
        type Error = ReplicationError;

        fn send(&mut self, message: RaftMessage) -> Result<(), Self::Error> {
            let recipient = (message.to - 1) as usize;
            self.senders[recipient]
                .send(message)
                .map_err(|e| ReplicationError::SendMessage(IOError::new(ErrorKind::NetworkDown, e)))
        }

        fn recv(&mut self) -> Result<Option<RaftMessage>, Self::Error> {
            self.receiver
                .recv()
                .map_err(|e| ReplicationError::RecvMessage(IOError::new(ErrorKind::NetworkDown, e)))
                .map(Some)
        }

        fn try_recv(&mut self) -> Result<Option<RaftMessage>, Self::Error> {
            let res = self.receiver.try_recv();
            match res {
                Ok(message) => Ok(Some(message)),
                Err(TryRecvError::Empty) => Ok(None),
                Err(e) => {
                    Err(ReplicationError::RecvMessage(IOError::new(ErrorKind::NetworkDown, e)))
                },
            }
        }
    }
}
