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
    pub fn remove_peer(&mut self, msg: RemovePeerMsg) -> Result<()> {
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
