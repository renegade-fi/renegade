//! Peer index access methods on a transaction

use std::collections::HashMap;

use common::types::gossip::{ClusterId, PeerInfo, WrappedPeerId};
use libmdbx::{TransactionKind, RW};
use libp2p::core::Multiaddr;

use crate::{storage::error::StorageError, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE};

use super::StateTxn;

/// The error thrown when a requested peer could not be found in the peer info
/// table
const PEER_NOT_FOUND_ERR: &str = "could not find peer in peer info table";

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Returns whether the given peer is already indexed    
    pub fn contains_peer(&self, peer_id: &WrappedPeerId) -> Result<bool, StorageError> {
        self.get_peer_info(peer_id).map(|x| x.is_some())
    }

    /// Get a peer from the index
    pub fn get_peer_info(&self, peer_id: &WrappedPeerId) -> Result<Option<PeerInfo>, StorageError> {
        self.inner().read(PEER_INFO_TABLE, peer_id)
    }

    /// Get all the known peers in a given cluster
    pub fn get_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<WrappedPeerId>, StorageError> {
        self.inner().read(CLUSTER_MEMBERSHIP_TABLE, cluster_id).map(|x| x.unwrap_or_default())
    }

    /// Get all the peers known to the local node
    pub fn get_all_peer_ids(&self) -> Result<Vec<WrappedPeerId>, StorageError> {
        // Create a cursor and take only the values
        let peer_cursor =
            self.inner().cursor::<WrappedPeerId, PeerInfo>(PEER_INFO_TABLE)?.into_iter();
        let peers = peer_cursor.keys().collect::<Result<Vec<_>, _>>()?;

        Ok(peers)
    }

    /// Get a map from peer ID to the peer's info
    ///
    /// This is constructed when a heartbeat is built and sent out
    ///
    /// TODO: This method will be expensive with scale, we may want to cache the
    /// heartbeat message
    pub fn get_info_map(&self) -> Result<HashMap<WrappedPeerId, PeerInfo>, StorageError> {
        let peer_cursor = self.inner().cursor::<WrappedPeerId, PeerInfo>(PEER_INFO_TABLE).unwrap();

        let mut res = HashMap::new();
        for elem in peer_cursor {
            let (id, peer) = elem?;
            res.insert(id, peer);
        }

        Ok(res)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Write a peer to the index
    pub fn write_peer(&self, peer: &PeerInfo) -> Result<(), StorageError> {
        self.inner().write(PEER_INFO_TABLE, &peer.peer_id, peer)
    }

    /// Remove a peer from the index
    pub fn remove_peer(&self, peer_id: &WrappedPeerId) -> Result<(), StorageError> {
        self.inner().delete(PEER_INFO_TABLE, peer_id).map(|_| ())
    }

    /// Append a peer to the given cluster list
    pub fn add_to_cluster(
        &self,
        peer_id: &WrappedPeerId,
        cluster_id: &ClusterId,
    ) -> Result<(), StorageError> {
        self.add_to_set(CLUSTER_MEMBERSHIP_TABLE, cluster_id, peer_id)
    }

    /// Remove a peer from the given cluster list
    pub fn remove_from_cluster(
        &self,
        peer_id: &WrappedPeerId,
        cluster_id: &ClusterId,
    ) -> Result<(), StorageError> {
        self.remove_from_set(CLUSTER_MEMBERSHIP_TABLE, cluster_id, peer_id)
    }

    /// Update the peer's address
    pub fn update_peer_addr(
        &self,
        peer_id: &WrappedPeerId,
        addr: Multiaddr,
    ) -> Result<(), StorageError> {
        let mut peer_info = self
            .get_peer_info(peer_id)?
            .ok_or(StorageError::NotFound(PEER_NOT_FOUND_ERR.into()))?;
        peer_info.addr = addr;
        self.write_peer(&peer_info)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use common::types::gossip::mocks::mock_peer;
    use libp2p::Multiaddr;

    use crate::{test_helpers::mock_db, CLUSTER_MEMBERSHIP_TABLE, PEER_INFO_TABLE};

    /// Test adding a peer to the index
    #[test]
    fn test_add_peer() {
        let db = mock_db();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write a peer to the index
        let peer = mock_peer();
        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer).unwrap();
        tx.commit().unwrap();

        // Read the peer back
        let tx = db.new_read_tx().unwrap();
        assert!(tx.contains_peer(&peer.peer_id).unwrap());

        let res = tx.get_peer_info(&peer.peer_id).unwrap();
        assert_eq!(res, Some(peer));
    }

    /// Tests adding a peer to a cluster
    #[test]
    fn test_add_cluster_peer() {
        let db = mock_db();
        db.create_table(CLUSTER_MEMBERSHIP_TABLE).unwrap();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write a peer to the index and add it to a cluster
        let peer = mock_peer();
        let cluster_id = peer.cluster_id.clone();

        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer).unwrap();
        tx.add_to_cluster(&peer.peer_id, &cluster_id).unwrap();
        tx.commit().unwrap();

        // Read the peer back and check cluster membership
        let tx = db.new_read_tx().unwrap();

        let cluster_members = tx.get_cluster_peers(&cluster_id).unwrap();
        assert_eq!(cluster_members, vec![peer.peer_id]);
    }

    /// Tests removing a cluster peer
    #[test]
    fn test_remove_cluster_peer() {
        let db = mock_db();
        db.create_table(CLUSTER_MEMBERSHIP_TABLE).unwrap();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write two peers to the index and add them to a cluster
        let peer1 = mock_peer();
        let mut peer2 = mock_peer();
        peer2.cluster_id = peer1.cluster_id.clone();
        let cluster_id = peer1.cluster_id.clone();

        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer1).unwrap();
        tx.add_to_cluster(&peer1.peer_id, &cluster_id).unwrap();
        tx.write_peer(&peer2).unwrap();
        tx.add_to_cluster(&peer2.peer_id, &cluster_id).unwrap();
        tx.commit().unwrap();

        // Remove one peer from the cluster
        let tx = db.new_write_tx().unwrap();
        tx.remove_from_cluster(&peer1.peer_id, &cluster_id).unwrap();
        tx.commit().unwrap();

        // Read the remaining peer back and check cluster membership
        let tx = db.new_read_tx().unwrap();

        let cluster_members = tx.get_cluster_peers(&cluster_id).unwrap();
        assert_eq!(cluster_members, vec![peer2.peer_id]);
    }

    /// Tests getting all peer ids
    #[test]
    fn test_get_all_peer_ids() {
        let db = mock_db();
        db.create_table(CLUSTER_MEMBERSHIP_TABLE).unwrap();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write two peers to the index
        let peer1 = mock_peer();
        let peer2 = mock_peer();

        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer1).unwrap();
        tx.write_peer(&peer2).unwrap();
        tx.commit().unwrap();

        // Get all peer ids
        let tx = db.new_read_tx().unwrap();
        let all_peer_ids = tx.get_all_peer_ids().unwrap();

        // Check if all peer ids are retrieved
        assert_eq!(all_peer_ids.len(), 2);
        assert!(all_peer_ids.contains(&peer1.peer_id));
        assert!(all_peer_ids.contains(&peer2.peer_id));
    }

    /// Tests getting a peer info map
    #[test]
    fn test_get_info_map() {
        let db = mock_db();
        db.create_table(CLUSTER_MEMBERSHIP_TABLE).unwrap();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write two peers to the index
        let peer1 = mock_peer();
        let peer2 = mock_peer();

        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer1).unwrap();
        tx.write_peer(&peer2).unwrap();
        tx.commit().unwrap();

        // Get the info map
        let tx = db.new_read_tx().unwrap();
        let info_map = tx.get_info_map().unwrap();

        // Check if all peer ids are retrieved
        assert_eq!(info_map.len(), 2);
        assert_eq!(info_map.get(&peer1.peer_id), Some(&peer1));
        assert_eq!(info_map.get(&peer2.peer_id), Some(&peer2));
    }

    /// Tests updating a peer's address
    #[test]
    fn test_update_peer_addr() {
        let db = mock_db();
        db.create_table(PEER_INFO_TABLE).unwrap();

        // Write a peer to the index
        let peer = mock_peer();
        let tx = db.new_write_tx().unwrap();
        tx.write_peer(&peer).unwrap();
        tx.commit().unwrap();

        // Update the peer's address
        let new_addr = Multiaddr::from(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        let tx = db.new_write_tx().unwrap();
        tx.update_peer_addr(&peer.peer_id, new_addr.clone()).unwrap();
        tx.commit().unwrap();

        // Read the peer back
        let tx = db.new_read_tx().unwrap();
        let res = tx.get_peer_info(&peer.peer_id).unwrap().unwrap();
        assert_eq!(res.addr, new_addr);
    }
}
