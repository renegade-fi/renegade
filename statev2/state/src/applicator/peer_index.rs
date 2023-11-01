//! Applicator methods for the peer index, separated out for discoverability

use std::str::FromStr;

use crate::storage::db::DbTxn;

use super::{
    error::StateApplicatorError, Result, StateApplicator, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE,
};
use common::types::gossip::{PeerInfo, WrappedPeerId};
use external_api::bus_message::{SystemBusMessage, NETWORK_TOPOLOGY_TOPIC};
use itertools::Itertools;
use libmdbx::RW;
use state_proto::{AddPeers as AddPeersMsg, RemovePeer as RemovePeerMsg};

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add new peers to the peer index
    pub fn add_peers(&self, msg: AddPeersMsg) -> Result<()> {
        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;

        // Index each peer
        for peer in msg.peers.into_iter() {
            // Parse the peer info and mark a successful heartbeat
            let peer_info = PeerInfo::try_from(peer).map_err(StateApplicatorError::Proto)?;
            peer_info.successful_heartbeat();

            // Do not index the peer if the given address is not dialable
            if !peer_info.is_dialable(self.config.allow_local) {
                continue;
            }

            // Add the peer to the store
            Self::add_peer_with_tx(peer_info.clone(), &tx)?;
            self.system_bus().publish(
                NETWORK_TOPOLOGY_TOPIC.to_string(),
                SystemBusMessage::NewPeer { peer: peer_info },
            );
        }

        tx.commit().map_err(StateApplicatorError::Storage)
    }

    /// Remove a peer from the peer index
    pub fn remove_peer(&self, msg: RemovePeerMsg) -> Result<()> {
        let peer_id = WrappedPeerId::from_str(&msg.peer_id)
            .map_err(|e| StateApplicatorError::Parse(format!("PeerId: {}", e)))?;
        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;

        Self::remove_peer_with_tx(peer_id, &tx)?;
        tx.commit().map_err(StateApplicatorError::Storage)?;

        // Push a message to the bus
        self.system_bus().publish(
            NETWORK_TOPOLOGY_TOPIC.to_string(),
            SystemBusMessage::PeerExpired { peer: peer_id },
        );
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Add a single peer to the global state
    fn add_peer_with_tx(peer: PeerInfo, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Add the peer to the peer index
        tx.write(PEER_INFO_TABLE, &peer.peer_id, &peer)
            .map_err(StateApplicatorError::Storage)?;

        // Read in the cluster peers list and append the new peer
        let cluster_id = &peer.cluster_id;
        let peer_id = peer.peer_id;

        let mut peers: Vec<WrappedPeerId> = tx
            .read(CLUSTER_MEMBERSHIP_TABLE, cluster_id)?
            .unwrap_or_default();
        if !peers.contains(&peer_id) {
            peers.push(peer_id);
            tx.write(CLUSTER_MEMBERSHIP_TABLE, cluster_id, &peers)?;
        }

        Ok(())
    }

    /// Remove a single peer from the global state
    fn remove_peer_with_tx(peer_id: WrappedPeerId, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Remove the peer from the peer index
        if let Some(info) = tx.read::<_, PeerInfo>(PEER_INFO_TABLE, &peer_id)? {
            tx.delete(PEER_INFO_TABLE, &peer_id)
                .map_err(StateApplicatorError::Storage)?;

            // Remove the peer from its cluster's list
            let cluster_id = info.cluster_id;
            let peers: Vec<WrappedPeerId> = tx
                .read(CLUSTER_MEMBERSHIP_TABLE, &cluster_id)?
                .unwrap_or_default();

            let peers = peers.into_iter().filter(|p| p != &peer_id).collect_vec();
            tx.write(CLUSTER_MEMBERSHIP_TABLE, &cluster_id, &peers)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use common::types::gossip::{PeerInfo, WrappedPeerId};
    use multiaddr::Multiaddr;
    use state_proto::{AddPeers, AddPeersBuilder, ClusterId, PeerId, PeerInfoBuilder, RemovePeer};

    use crate::applicator::{
        test_helpers::mock_applicator, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE,
    };

    // -----------
    // | Helpers |
    // -----------

    /// Create a mock `AddPeers` message for a single peer
    ///
    /// Returns both the message and the peer's info
    fn add_peer_msg() -> (AddPeers, PeerInfo) {
        // Build an RPC message to add a peer
        let cluster_id = "1234".to_string();
        let peer_id = WrappedPeerId::random().to_string();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let addr = Multiaddr::from(addr);

        let peer_info = PeerInfoBuilder::default()
            .cluster_id(ClusterId {
                id: cluster_id.clone(),
            })
            .peer_id(PeerId {
                id: peer_id.clone(),
            })
            .addr(addr.to_string())
            .build()
            .unwrap();

        let msg = AddPeersBuilder::default()
            .peers(vec![peer_info.clone()])
            .build()
            .unwrap();

        (msg, PeerInfo::try_from(peer_info).unwrap())
    }

    /// Create a mock `RemovePeer` message
    fn remove_peer_msg(peer_id: &WrappedPeerId) -> RemovePeer {
        RemovePeer {
            peer_id: peer_id.to_string(),
        }
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests adding a new peer to the state
    #[test]
    fn test_add_peer() {
        let applicator = mock_applicator();

        let (msg, peer_info) = add_peer_msg();
        applicator.add_peers(msg).unwrap();

        // Search for the peer in the db as well as its cluster info
        let db = applicator.db();
        let info: PeerInfo = db
            .read(PEER_INFO_TABLE, &peer_info.peer_id)
            .unwrap()
            .unwrap();
        let cluster_peers: Vec<WrappedPeerId> = db
            .read(CLUSTER_MEMBERSHIP_TABLE, &peer_info.cluster_id)
            .unwrap()
            .unwrap();

        assert_eq!(info, peer_info);
        assert_eq!(cluster_peers, vec![peer_info.peer_id]);
    }

    /// Tests removing a nonexistent peer from the state
    #[test]
    fn test_remove_nonexistent_peer() {
        let applicator = mock_applicator();

        // Removing the peer should not fail
        let peer_id = WrappedPeerId::random();
        let msg = remove_peer_msg(&peer_id);
        applicator.remove_peer(msg).unwrap();
    }

    /// Tests removing a peer that does exist
    #[test]
    fn test_remove_peer() {
        let applicator = mock_applicator();

        // Add two peers to the state
        let (mut add_msg1, peer_info1) = add_peer_msg();
        let (add_msg2, peer_info2) = add_peer_msg();

        add_msg1.peers.extend(add_msg2.peers);

        applicator.add_peers(add_msg1).unwrap();

        // Remove the first peer from the state
        let remove_msg = remove_peer_msg(&peer_info1.peer_id);
        applicator.remove_peer(remove_msg).unwrap();

        // Verify that the first peer isn't present, but the second s
        let db = applicator.db();
        let info1: Option<PeerInfo> = db.read(PEER_INFO_TABLE, &peer_info1.peer_id).unwrap();
        let info2: PeerInfo = db
            .read(PEER_INFO_TABLE, &peer_info2.peer_id)
            .unwrap()
            .unwrap();

        assert!(info1.is_none());
        assert_eq!(info2, peer_info2);

        // Verify that the cluster membership for the peers' cluster only contains the
        // second peer
        let cluster_peers: Vec<WrappedPeerId> = db
            .read(CLUSTER_MEMBERSHIP_TABLE, &peer_info1.cluster_id)
            .unwrap()
            .unwrap();

        assert_eq!(cluster_peers, vec![peer_info2.peer_id]);
    }
}
