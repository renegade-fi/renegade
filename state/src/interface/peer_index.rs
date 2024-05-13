//! State interface for peer index methods
//!
//! Peer index sets do not need to go through raft consensus, so they are
//! set directly via this interface. This is because the peer index interface is
//! one of unconditional writes only and inconsistent state is okay between
//! cluster peers

use std::collections::HashMap;

use common::types::gossip::{ClusterId, PeerInfo, WrappedPeerId};
use external_api::bus_message::{SystemBusMessage, NETWORK_TOPOLOGY_TOPIC};
use gossip_api::request_response::heartbeat::HeartbeatMessage;
use itertools::Itertools;
use util::runtime::block_current;

use crate::{
    error::StateError,
    replicationv2::{get_raft_id, raft::NetworkEssential, RaftNode},
    StateHandle,
};

impl<N: NetworkEssential> StateHandle<N> {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer info for a given peer
    pub async fn get_peer_info(
        &self,
        peer_id: &WrappedPeerId,
    ) -> Result<Option<PeerInfo>, StateError> {
        let peer_id = *peer_id;
        self.with_read_tx(move |tx| {
            let peer_info = tx.get_peer_info(&peer_id)?;
            Ok(peer_info)
        })
        .await
    }

    /// Get all the peers in the peer index
    pub async fn get_all_peers_ids(
        &self,
        include_self: bool,
    ) -> Result<Vec<WrappedPeerId>, StateError> {
        self.with_read_tx(move |tx| {
            let mut map = tx.get_info_map()?;
            if !include_self {
                map.remove(&tx.get_peer_id()?);
            }
            Ok(map.into_keys().collect())
        })
        .await
    }

    /// Get the peer info map from the peer index
    pub async fn get_peer_info_map(&self) -> Result<HashMap<WrappedPeerId, PeerInfo>, StateError> {
        self.with_read_tx(move |tx| {
            let info_map = tx.get_info_map()?;
            Ok(info_map)
        })
        .await
    }

    // --- Heartbeat --- //

    /// Get all the peers known in a given cluster
    pub async fn get_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<WrappedPeerId>, StateError> {
        let cluster_id = cluster_id.clone();
        self.with_read_tx(move |tx| {
            let peers = tx.get_cluster_peers(&cluster_id)?;
            Ok(peers)
        })
        .await
    }

    /// Get all the peers _not_ in the given cluster
    pub async fn get_non_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<WrappedPeerId>, StateError> {
        let cluster_id = cluster_id.clone();
        self.with_read_tx(move |tx| {
            let mut info = tx.get_info_map()?;
            info.retain(|_, peer_info| peer_info.get_cluster_id() != cluster_id);
            Ok(info.into_keys().collect())
        })
        .await
    }

    /// Given a list of peers, return the ones that are not in the peer index
    pub async fn get_missing_peers(
        &self,
        peers: &[WrappedPeerId],
    ) -> Result<Vec<WrappedPeerId>, StateError> {
        let peers = peers.to_vec();
        self.with_read_tx(move |tx| {
            let mut res = Vec::new();
            for peer in peers.iter().copied() {
                if tx.get_peer_info(&peer)?.is_none() {
                    res.push(peer);
                }
            }
            Ok(res)
        })
        .await
    }

    /// Construct a heartbeat message from the state
    ///
    /// TODO: Cache this if it becomes a bottleneck
    pub async fn construct_heartbeat(&self) -> Result<HeartbeatMessage, StateError> {
        self.with_read_tx(move |tx| {
            let peers = tx.get_info_map()?;
            let orders = tx.get_all_orders()?;

            // Filter out cancelled orders
            let known_peers = peers.into_keys().collect_vec();
            let known_orders =
                orders.into_iter().filter(|order| !order.is_cancelled()).map(|o| o.id).collect();

            Ok(HeartbeatMessage { known_peers, known_orders })
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a peer to the peer index
    pub async fn add_peer(&self, peer: PeerInfo) -> Result<(), StateError> {
        self.add_peer_batch(vec![peer]).await
    }

    /// Add a batch of peers to the index
    pub async fn add_peer_batch(&self, peers: Vec<PeerInfo>) -> Result<(), StateError> {
        // Index each peer
        let this = self.clone();
        self.with_write_tx(move |tx| {
            for mut peer in peers.into_iter() {
                // Parse the peer info and mark a successful heartbeat
                peer.successful_heartbeat();

                // Do not index the peer if the given address is not dialable
                if !peer.is_dialable(this.allow_local) {
                    continue;
                }

                // Add the peer to the store
                tx.write_peer(&peer)?;
                tx.add_to_cluster(&peer.peer_id, &peer.cluster_id)?;

                // If the peer belongs in the same cluster, add it to the raft group
                let my_cluster_id = tx.get_cluster_id()?;
                if peer.cluster_id == my_cluster_id {
                    let raft_id = get_raft_id(&peer.peer_id);
                    let info = RaftNode::new(peer.peer_id);
                    block_current(this.raft.add_learner(raft_id, info))?;
                }

                this.bus.publish(
                    NETWORK_TOPOLOGY_TOPIC.to_string(),
                    SystemBusMessage::NewPeer { peer },
                );
            }
            Ok(())
        })
        .await
    }

    /// Remove a peer that has been expired
    pub async fn remove_peer(&self, peer_id: WrappedPeerId) -> Result<(), StateError> {
        let this = self.clone();
        self.with_write_tx(move |tx| {
            let my_cluster = tx.get_cluster_id()?;
            if let Some(peer_info) = tx.get_peer_info(&peer_id)? {
                // If the peer is in the same cluster, remove it from the raft group
                if peer_info.cluster_id == my_cluster {
                    let raft_id = get_raft_id(&peer_id);
                    block_current(this.raft.remove_peer(raft_id))?;
                }

                tx.remove_from_cluster(&peer_id, &peer_info.cluster_id)?;
                tx.remove_peer(&peer_id)?;
            }

            // Commit and send a message to the bus
            this.bus.publish(
                NETWORK_TOPOLOGY_TOPIC.to_string(),
                SystemBusMessage::PeerExpired { peer: peer_id },
            );

            Ok(())
        })
        .await
    }

    /// Record a successful heartbeat on a peer
    pub async fn record_heartbeat(&self, peer_id: &WrappedPeerId) -> Result<(), StateError> {
        let peer_id = *peer_id;
        self.with_write_tx(move |tx| {
            if let Some(mut peer) = tx.get_peer_info(&peer_id)? {
                peer.successful_heartbeat();
                tx.write_peer(&peer)?;
            }
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use common::types::gossip::{mocks::mock_peer, ClusterId};

    use crate::test_helpers::mock_state;

    /// Tests adding a peer to the peer index
    #[tokio::test]
    async fn test_add_peer() {
        let state = mock_state().await;
        let peer1 = mock_peer();
        let mut peer2 = mock_peer();
        let mut peer3 = mock_peer();

        peer2.cluster_id = ClusterId::from_str("test-cluster-2").unwrap();
        peer3.cluster_id = peer1.cluster_id.clone();

        // Add the peers
        state.add_peer(peer1.clone()).await.unwrap();
        state.add_peer(peer2.clone()).await.unwrap();
        state.add_peer(peer3.clone()).await.unwrap();

        // Check that the first peer was added
        let peer_info = state.get_peer_info(&peer1.peer_id).await.unwrap().unwrap();
        assert_eq!(peer_info, peer1);

        // Check the cluster peers method
        let cluster_peers = state.get_cluster_peers(&peer1.cluster_id).await.unwrap();
        assert_eq!(cluster_peers, vec![peer1.peer_id, peer3.peer_id]);

        // Check the non-cluster peers method
        let non_cluster_peers = state.get_non_cluster_peers(&peer1.cluster_id).await.unwrap();
        assert_eq!(non_cluster_peers, vec![peer2.peer_id]);

        // Check the info map
        let info_map = state.get_peer_info_map().await.unwrap();
        assert_eq!(info_map.len(), 3);
        assert_eq!(info_map.get(&peer1.peer_id), Some(&peer1));
        assert_eq!(info_map.get(&peer2.peer_id), Some(&peer2));
        assert_eq!(info_map.get(&peer3.peer_id), Some(&peer3));
    }

    /// Tests removing a peer from the state
    #[tokio::test]
    async fn test_remove_peer() {
        let state = mock_state().await;
        let peer1 = mock_peer();
        let mut peer2 = mock_peer();
        let mut peer3 = mock_peer();

        peer2.cluster_id = ClusterId::from_str("test-cluster-2").unwrap();
        peer3.cluster_id = peer1.cluster_id.clone();

        // Add the peers
        state.add_peer(peer1.clone()).await.unwrap();
        state.add_peer(peer2.clone()).await.unwrap();
        state.add_peer(peer3.clone()).await.unwrap();

        // Remove a peer
        state.remove_peer(peer1.peer_id).await.unwrap();

        // Check that the peer was removed
        let peer_info = state.get_peer_info(&peer1.peer_id).await.unwrap();
        assert!(peer_info.is_none());

        // Check the cluster peers method
        let cluster_peers = state.get_cluster_peers(&peer1.cluster_id).await.unwrap();
        assert_eq!(cluster_peers, vec![peer3.peer_id]);

        // Check the non-cluster peers method
        let non_cluster_peers = state.get_non_cluster_peers(&peer1.cluster_id).await.unwrap();
        assert_eq!(non_cluster_peers, vec![peer2.peer_id]);

        // Check the info map
        let info_map = state.get_peer_info_map().await.unwrap();
        assert_eq!(info_map.len(), 2);
        assert_eq!(info_map.get(&peer1.peer_id), None);
        assert_eq!(info_map.get(&peer2.peer_id), Some(&peer2));
        assert_eq!(info_map.get(&peer3.peer_id), Some(&peer3));
    }

    /// Tests the `get_missing_peers` method
    #[tokio::test]
    async fn test_get_missing_peers() {
        let state = mock_state().await;
        let peer1 = mock_peer();
        let peer2 = mock_peer();
        let peer3 = mock_peer();

        // Add the peer
        state.add_peer(peer1.clone()).await.unwrap();

        // Check that the missing peers are returned
        let mut missing_peers =
            state.get_missing_peers(&[peer1.peer_id, peer2.peer_id, peer3.peer_id]).await.unwrap();
        missing_peers.sort();
        let mut expected = vec![peer2.peer_id, peer3.peer_id];
        expected.sort();

        assert_eq!(missing_peers, expected);
    }
}
