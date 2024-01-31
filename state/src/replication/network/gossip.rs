//! Implements a translation layer between the gossip network and the raft
//! networking

use std::io::{Error as IOError, ErrorKind};

use crossbeam::channel::TryRecvError;
use gossip_api::request_response::{raft::RaftMessage, GossipRequest};
use job_types::network_manager::{NetworkManagerJob, NetworkManagerQueue};
use raft::eraftpb::Message as RawRaftMessage;

use crate::replication::error::ReplicationError;

use super::{
    address_translation::SharedPeerIdTranslationMap,
    traits::{RaftMessageReceiver, RaftNetwork},
};

/// The error message emitted when a peer address cannot be found in the
/// translation map
const ERR_PEER_NOT_FOUND: &str = "Peer not found in translation map";

/// An implementation of the `RaftNetwork` trait that connects to the network
/// manager
///
/// This connection is brokered by queues, one managed in the network manager
/// for inbound, and the other managed here
///
/// The `GossipRaftNetwork` also serves as a translation layer between the
/// raft's peer IDs and the libp2p peer IDs used for gossip more broadly
pub struct GossipRaftNetwork {
    /// The outbound network manager's channel
    outbound: NetworkManagerQueue,
    /// The inbound queue for raft messages
    inbound: RaftMessageReceiver,
    /// The address translation layer, used to translate between raft IDs and
    /// peer IDs
    address_map: SharedPeerIdTranslationMap,
}

impl GossipRaftNetwork {
    /// Construct the network
    pub fn new(
        outbound: NetworkManagerQueue,
        inbound: RaftMessageReceiver,
        address_map: SharedPeerIdTranslationMap,
    ) -> Self {
        Self { outbound, inbound, address_map }
    }
}

impl RaftNetwork for GossipRaftNetwork {
    type Error = ReplicationError;

    fn recv(&mut self) -> Result<Option<RawRaftMessage>, Self::Error> {
        let inbound = self
            .inbound
            .recv()
            .map_err(|e| ReplicationError::RecvMessage(IOError::new(ErrorKind::NetworkDown, e)))?;
        Ok(Some(inbound.into_inner()))
    }

    fn try_recv(&mut self) -> Result<Option<RawRaftMessage>, Self::Error> {
        let res = self.inbound.try_recv();
        match res {
            Ok(message) => Ok(Some(message.into_inner())),
            Err(TryRecvError::Empty) => Ok(None),
            Err(e) => Err(ReplicationError::RecvMessage(IOError::new(ErrorKind::NetworkDown, e))),
        }
    }

    fn send(&mut self, message: RawRaftMessage) -> Result<(), Self::Error> {
        let peer = self.address_map.read().unwrap().get_peer_id(message.to).ok_or_else(|| {
            ReplicationError::SendMessage(IOError::new(ErrorKind::NotFound, ERR_PEER_NOT_FOUND))
        })?;

        let wrapped = RaftMessage::new(message);
        let job = NetworkManagerJob::request(peer, GossipRequest::Raft(wrapped));
        self.outbound
            .send(job)
            .map_err(|e| ReplicationError::SendMessage(IOError::new(ErrorKind::NetworkDown, e)))
    }
}
