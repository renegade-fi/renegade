//! Groups handlers for gossiping about cluster management events

use std::collections::hash_map::Entry;

use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::{
    api::{
        cluster_management::{ClusterJoinMessage, ReplicateMessage},
        gossip::{GossipOutbound, GossipRequest, PubsubMessage},
    },
    state::{RelayerState, Wallet},
};

use super::{
    errors::GossipError,
    jobs::ClusterManagementJob,
    server::GossipProtocolExecutor,
    types::{PeerInfo, WrappedPeerId},
};

/// Cluster management implementation of the protocol executor
impl GossipProtocolExecutor {
    /// Handles an incoming cluster management job
    pub(super) fn handle_cluster_management_job(
        job: ClusterManagementJob,
        network_channel: UnboundedSender<GossipOutbound>,
        global_state: &RelayerState,
    ) -> Result<(), GossipError> {
        match job {
            ClusterManagementJob::ClusterJoinRequest(req) => {
                Self::handle_cluster_join_job(req, global_state, network_channel)?;
            }
            ClusterManagementJob::ReplicateRequest(req) => {
                Self::handle_replicate_request(req, global_state, network_channel)?;
            }
            ClusterManagementJob::AddWalletReplica { wallet_id, peer_id } => {
                Self::handle_add_replica_job(peer_id, wallet_id, global_state)
            }
        }

        Ok(())
    }

    /// Handles a cluster management job to add a new node to the local peer's cluster
    fn handle_cluster_join_job(
        message: ClusterJoinMessage,
        global_state: &RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        {
            // The cluster join request is authenticated at the network layer
            // by the `NetworkManager`, so no authentication needs to be done.
            // Simply update the local peer info to reflect the new node's membership
            let mut locked_peers = global_state.write_known_peers();
            let mut locked_cluster_metadata = global_state.write_cluster_metadata();

            // Insert the new peer into the cluster metadata and peer metadata
            locked_cluster_metadata.add_member(message.peer_id);
            locked_peers.entry(message.peer_id).or_insert_with(|| {
                PeerInfo::new(
                    message.peer_id,
                    message.cluster_id.clone(),
                    message.addr.clone(),
                )
            });
        }

        // Request that the peer replicate all locally replicated wallets
        let locked_wallets = global_state.read_managed_wallets();
        let wallets: Vec<Wallet> = locked_wallets.values().cloned().collect();
        Self::send_replicate_request(message.peer_id, wallets, network_channel)
    }

    /// Send a request to the given peer to replicate a set of wallets
    fn send_replicate_request(
        peer: WrappedPeerId,
        wallets: Vec<Wallet>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        network_channel
            .send(GossipOutbound::Request {
                peer_id: peer,
                message: GossipRequest::Replicate(ReplicateMessage { wallets }),
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))
    }

    /// Handles a request from a peer to replicate a given set of wallets
    fn handle_replicate_request(
        req: ReplicateMessage,
        global_state: &RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        // Add wallets to global state
        let mut wallets_locked = global_state.write_managed_wallets();
        for wallet in req.wallets.iter() {
            if let Entry::Vacant(e) = wallets_locked.entry(wallet.wallet_id) {
                e.insert(wallet.clone());
            }

            wallets_locked
                .get_mut(&wallet.wallet_id)
                .unwrap()
                .metadata
                .replicas
                .insert(*global_state.read_peer_id());
        }

        // Broadcast a message to the network indicating that the wallet is now replicated
        let topic = global_state
            .read_cluster_metadata()
            .id
            .get_management_topic();

        network_channel
            .send(GossipOutbound::Pubsub {
                topic,
                message: PubsubMessage::Replicated {
                    peer_id: *global_state.read_peer_id(),
                    wallets: req.wallets,
                },
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        Ok(())
    }

    /// Handles an incoming job to update a wallet's replicas with a newly added peer
    fn handle_add_replica_job(
        peer_id: WrappedPeerId,
        wallet_id: Uuid,
        global_state: &RelayerState,
    ) {
        let mut locked_wallets = global_state.write_managed_wallets();
        if !locked_wallets.contains_key(&wallet_id) {
            return;
        }

        locked_wallets
            .get_mut(&wallet_id)
            .unwrap()
            .metadata
            .replicas
            .insert(peer_id);
    }
}
