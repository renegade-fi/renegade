//! Applicator methods for the peer index, separated out for discoverability

use super::{Result, StateApplicator};
use common::types::gossip::{PeerInfo, WrappedPeerId};
use external_api::bus_message::{SystemBusMessage, NETWORK_TOPOLOGY_TOPIC};

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add new peers to the peer index
    pub fn add_peers(&self, peers: Vec<PeerInfo>) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Index each peer
        for mut peer_info in peers.into_iter() {
            // Parse the peer info and mark a successful heartbeat
            peer_info.successful_heartbeat();

            // Do not index the peer if the given address is not dialable
            if !peer_info.is_dialable(self.config.allow_local) {
                continue;
            }

            // Add the peer to the store
            tx.write_peer(&peer_info)?;
            tx.add_to_cluster(&peer_info.peer_id, &peer_info.cluster_id)?;
            self.system_bus().publish(
                NETWORK_TOPOLOGY_TOPIC.to_string(),
                SystemBusMessage::NewPeer { peer: peer_info },
            );
        }

        Ok(tx.commit()?)
    }

    /// Remove a peer from the peer index
    pub fn remove_peer(&self, peer_id: WrappedPeerId) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Remove from the cluster then remove the peer info itself
        if let Some(peer_info) = tx.get_peer_info(&peer_id)? {
            tx.remove_from_cluster(&peer_id, &peer_info.cluster_id)?;
            tx.remove_peer(&peer_id)?;
        }

        tx.commit()?;

        // Push a message to the bus
        self.system_bus().publish(
            NETWORK_TOPOLOGY_TOPIC.to_string(),
            SystemBusMessage::PeerExpired { peer: peer_id },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        applicator::test_helpers::mock_applicator, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE,
    };
    use common::types::gossip::{mocks::mock_peer, PeerInfo, WrappedPeerId};

    // ---------
    // | Tests |
    // ---------

    /// Tests adding a new peer to the state
    #[test]
    fn test_add_peer() {
        let applicator = mock_applicator();

        let mut peer = mock_peer();
        applicator.add_peers(vec![peer.clone()]).unwrap();

        // Search for the peer in the db as well as its cluster info
        let db = applicator.db();
        let info: PeerInfo = db.read(PEER_INFO_TABLE, &peer.peer_id).unwrap().unwrap();
        let cluster_peers: Vec<WrappedPeerId> =
            db.read(CLUSTER_MEMBERSHIP_TABLE, &peer.cluster_id).unwrap().unwrap();

        // Set the heartbeat as the state will have update it
        peer.last_heartbeat = info.last_heartbeat;
        assert_eq!(info, peer);
        assert_eq!(cluster_peers, vec![peer.peer_id]);
    }

    /// Tests removing a nonexistent peer from the state
    #[test]
    fn test_remove_nonexistent_peer() {
        let applicator = mock_applicator();

        // Removing the peer should not fail
        let peer_id = WrappedPeerId::random();
        applicator.remove_peer(peer_id).unwrap();
    }

    /// Tests removing a peer that does exist
    #[test]
    fn test_remove_peer() {
        let applicator = mock_applicator();

        // Add two peers to the state
        let peer1 = mock_peer();
        let mut peer2 = mock_peer();

        let peers = vec![peer1.clone(), peer2.clone()];

        applicator.add_peers(peers).unwrap();

        // Remove the first peer from the state
        applicator.remove_peer(peer1.peer_id).unwrap();

        // Verify that the first peer isn't present, but the second is
        let db = applicator.db();
        let info1: Option<PeerInfo> = db.read(PEER_INFO_TABLE, &peer1.peer_id).unwrap();
        let info2: PeerInfo = db.read(PEER_INFO_TABLE, &peer2.peer_id).unwrap().unwrap();

        // Set the heartbeat as the state will have updated it
        peer2.last_heartbeat = info2.last_heartbeat;

        assert!(info1.is_none());
        assert_eq!(info2, peer2);

        // Verify that the cluster membership for the peers' cluster only contains the
        // second peer
        let cluster_peers: Vec<WrappedPeerId> =
            db.read(CLUSTER_MEMBERSHIP_TABLE, &peer1.cluster_id).unwrap().unwrap();

        assert_eq!(cluster_peers, vec![peer2.peer_id]);
    }
}
