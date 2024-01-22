//! Applicator methods for the peer index, separated out for discoverability

use crate::storage::db::DbTxn;

use super::{
    error::StateApplicatorError, Result, StateApplicator, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE,
};
use common::types::gossip::{PeerInfo, WrappedPeerId};
use external_api::bus_message::{SystemBusMessage, NETWORK_TOPOLOGY_TOPIC};
use itertools::Itertools;
use libmdbx::RW;

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add new peers to the peer index
    pub fn add_peers(&self, peers: Vec<PeerInfo>) -> Result<()> {
        let tx = self.db().new_write_tx().map_err(StateApplicatorError::Storage)?;

        // Index each peer
        for peer_info in peers.into_iter() {
            // Parse the peer info and mark a successful heartbeat
            peer_info.successful_heartbeat();

            // Do not index the peer if the given address is not dialable
            if !peer_info.is_dialable(self.config.allow_local) {
                continue;
            }

            // Add the peer to the store
            Self::add_peer_with_tx(&peer_info, &tx)?;
            self.system_bus().publish(
                NETWORK_TOPOLOGY_TOPIC.to_string(),
                SystemBusMessage::NewPeer { peer: peer_info },
            );
        }

        tx.commit().map_err(StateApplicatorError::Storage)
    }

    /// Remove a peer from the peer index
    pub fn remove_peer(&self, peer_id: WrappedPeerId) -> Result<()> {
        let tx = self.db().new_write_tx().map_err(StateApplicatorError::Storage)?;

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
    fn add_peer_with_tx(peer: &PeerInfo, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Add the peer to the peer index
        tx.write(PEER_INFO_TABLE, &peer.peer_id, peer).map_err(StateApplicatorError::Storage)?;

        // Read in the cluster peers list and append the new peer
        let cluster_id = &peer.cluster_id;
        let peer_id = peer.peer_id;

        let mut peers: Vec<WrappedPeerId> =
            tx.read(CLUSTER_MEMBERSHIP_TABLE, cluster_id)?.unwrap_or_default();
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
            tx.delete(PEER_INFO_TABLE, &peer_id).map_err(StateApplicatorError::Storage)?;

            // Remove the peer from its cluster's list
            let cluster_id = info.cluster_id;
            let peers: Vec<WrappedPeerId> =
                tx.read(CLUSTER_MEMBERSHIP_TABLE, &cluster_id)?.unwrap_or_default();

            let peers = peers.into_iter().filter(|p| p != &peer_id).collect_vec();
            tx.write(CLUSTER_MEMBERSHIP_TABLE, &cluster_id, &peers)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        sync::atomic::Ordering,
    };

    use common::types::gossip::{ClusterId, PeerInfo, WrappedPeerId};
    use multiaddr::Multiaddr;

    use crate::applicator::{
        test_helpers::mock_applicator, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE,
    };

    // -----------
    // | Helpers |
    // -----------

    /// Build a mock peer's info
    fn mock_peer() -> PeerInfo {
        // Build an RPC message to add a peer
        let cluster_id = ClusterId::from_str("1234").unwrap();
        let peer_id = WrappedPeerId::random();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let addr = Multiaddr::from(addr);

        PeerInfo::new(peer_id, cluster_id, addr.clone(), vec![] /* signature */)
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests adding a new peer to the state
    #[test]
    fn test_add_peer() {
        let applicator = mock_applicator();

        let peer = mock_peer();
        applicator.add_peers(vec![peer.clone()]).unwrap();

        // Search for the peer in the db as well as its cluster info
        let db = applicator.db();
        let info: PeerInfo = db.read(PEER_INFO_TABLE, &peer.peer_id).unwrap().unwrap();
        let cluster_peers: Vec<WrappedPeerId> =
            db.read(CLUSTER_MEMBERSHIP_TABLE, &peer.cluster_id).unwrap().unwrap();

        // Set the heartbeat as the state will have update it
        peer.last_heartbeat.store(info.last_heartbeat.load(Ordering::Relaxed), Ordering::Relaxed);
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
        let peer2 = mock_peer();

        let peers = vec![peer1.clone(), peer2.clone()];

        applicator.add_peers(peers).unwrap();

        // Remove the first peer from the state
        applicator.remove_peer(peer1.peer_id).unwrap();

        // Verify that the first peer isn't present, but the second is
        let db = applicator.db();
        let info1: Option<PeerInfo> = db.read(PEER_INFO_TABLE, &peer1.peer_id).unwrap();
        let info2: PeerInfo = db.read(PEER_INFO_TABLE, &peer2.peer_id).unwrap().unwrap();

        // Set the heartbeat as the state will have updated it
        peer2.last_heartbeat.store(info2.last_heartbeat.load(Ordering::Relaxed), Ordering::Relaxed);

        assert!(info1.is_none());
        assert_eq!(info2, peer2);

        // Verify that the cluster membership for the peers' cluster only contains the
        // second peer
        let cluster_peers: Vec<WrappedPeerId> =
            db.read(CLUSTER_MEMBERSHIP_TABLE, &peer1.cluster_id).unwrap().unwrap();

        assert_eq!(cluster_peers, vec![peer2.peer_id]);
    }
}
