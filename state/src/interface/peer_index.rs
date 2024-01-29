//! State interface for peer index methods

use std::collections::HashMap;

use common::types::gossip::{ClusterId, PeerInfo, WrappedPeerId};
use gossip_api::request_response::heartbeat::HeartbeatMessage;

use crate::{
    error::StateError, notifications::ProposalWaiter, storage::error::StorageError, State,
    StateTransition,
};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer info for a given peer
    pub fn get_peer_info(&self, peer_id: &WrappedPeerId) -> Result<Option<PeerInfo>, StateError> {
        let tx = self.db.new_read_tx()?;
        let peer_info = tx.get_peer_info(peer_id)?;
        tx.commit()?;

        Ok(peer_info)
    }

    /// Get all the peers in the peer index
    pub fn get_all_peers_ids(&self, include_self: bool) -> Result<Vec<WrappedPeerId>, StateError> {
        let tx = self.db.new_read_tx()?;
        let mut map = tx.get_info_map()?;
        if !include_self {
            map.remove(&self.get_peer_id()?);
        }

        tx.commit()?;
        Ok(map.into_keys().collect())
    }

    /// Get the peer info map from the peer index
    pub fn get_peer_info_map(&self) -> Result<HashMap<WrappedPeerId, PeerInfo>, StateError> {
        let tx = self.db.new_read_tx()?;
        let info_map = tx.get_info_map()?;
        tx.commit()?;

        Ok(info_map)
    }

    /// Get all the peers known in a given cluster
    pub fn get_cluster_peers(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<WrappedPeerId>, StateError> {
        let tx = self.db.new_read_tx()?;
        let peers = tx.get_cluster_peers(cluster_id)?;
        tx.commit()?;

        Ok(peers)
    }

    /// Construct a heartbeat message from the state
    pub fn construct_heartbeat(&self) -> Result<HeartbeatMessage, StateError> {
        let info_map = self.get_peer_info_map()?;
        Ok(HeartbeatMessage { known_peers: info_map })
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a peer to the peer index
    pub fn add_peer(&self, peer: PeerInfo) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddPeers { peers: vec![peer] })
    }

    /// Remove a peer that has been expired
    pub fn remove_peer(&self, peer_id: WrappedPeerId) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::RemovePeer { peer_id })
    }

    /// Add a batch of peers to the index
    pub fn add_peer_batch(&self, peers: Vec<PeerInfo>) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AddPeers { peers })
    }

    /// Record a successful heartbeat on a peer
    pub fn record_heartbeat(&self, peer_id: &WrappedPeerId) -> Result<(), StateError> {
        let tx = self.db.new_write_tx()?;
        let mut peer = tx.get_peer_info(peer_id)?.ok_or_else(|| {
            StateError::Db(StorageError::NotFound(format!(
                "Peer {peer_id} not found in peer index",
            )))
        })?;

        peer.successful_heartbeat();
        tx.write_peer(&peer)?;

        tx.commit()?;
        Ok(())
    }
}
