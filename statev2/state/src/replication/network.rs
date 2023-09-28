//! The network abstraction of the replication layer; defines the interface for
//! sending and receiving raft messages from cluster peers

use raft::prelude::Message as RaftMessage;

use super::error::ReplicationError;

/// The central trait that must be implemented by any networking layer used
/// by the replication layer
pub trait RaftNetwork {
    /// The error type emitted by the network implementation
    type Error: Into<ReplicationError>;

    /// Send a raft message to a peer
    ///
    /// This method MAY NOT not block
    fn send(&mut self, message: RaftMessage) -> Result<(), Self::Error>;

    /// Receive a raft message from the network
    ///
    /// This method MAY block
    fn recv(&mut self) -> Result<Option<RaftMessage>, Self::Error>;

    /// Attempt to receive a raft message from the network
    ///
    /// This method MAY NOT block
    fn try_recv(&mut self) -> Result<Option<RaftMessage>, Self::Error>;
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crossbeam::channel::{
        unbounded, Receiver as CrossbeamReceiver, Sender as CrossbeamSender, TryRecvError,
    };
    use raft::prelude::Message as RaftMessage;
    use std::io::{Error as IOError, ErrorKind};

    use crate::replication::error::ReplicationError;

    use super::RaftNetwork;

    /// A mock network that is brokered by two channels
    pub struct MockNetwork {
        /// The sender channel
        sender: CrossbeamSender<RaftMessage>,
        /// The receiver channel                                    
        receiver: CrossbeamReceiver<RaftMessage>,
    }

    impl MockNetwork {
        /// Constructor
        pub fn new(
            sender: CrossbeamSender<RaftMessage>,
            receiver: CrossbeamReceiver<RaftMessage>,
        ) -> Self {
            Self { sender, receiver }
        }

        /// Create a double sided mock connection
        pub fn new_duplex_conn() -> (Self, Self) {
            let (s1, r1) = unbounded();
            let (s2, r2) = unbounded();

            (Self::new(s1, r2), Self::new(s2, r1))
        }
    }

    impl RaftNetwork for MockNetwork {
        type Error = ReplicationError;

        fn send(&mut self, message: RaftMessage) -> Result<(), Self::Error> {
            self.sender
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
                Err(e) => Err(ReplicationError::RecvMessage(IOError::new(
                    ErrorKind::NetworkDown,
                    e,
                ))),
            }
        }
    }
}
