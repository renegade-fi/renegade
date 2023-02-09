//! Groups handlers for gossiping about cluster management events

use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{
        cluster_management::{
            ClusterJoinMessage, ClusterManagementMessage, ReplicateRequestBody, ReplicatedMessage,
        },
        gossip::{GossipOutbound, GossipRequest, PubsubMessage},
    },
    state::{
        wallet::{Wallet, WalletIdentifier},
        RelayerState,
    },
};

use super::{
    errors::GossipError,
    jobs::ClusterManagementJob,
    server::GossipProtocolExecutor,
    types::{ClusterId, PeerInfo, WrappedPeerId},
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
            ClusterManagementJob::ClusterAuthSuccess(cluster_id, peer_id, peer_info) => {
                Self::add_peer_to_cluster(
                    peer_id,
                    peer_info,
                    cluster_id,
                    global_state,
                    network_channel,
                )?;
            }

            ClusterManagementJob::ClusterJoinRequest(cluster_id, req) => {
                Self::handle_cluster_join_job(cluster_id, req, global_state, network_channel)?;
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
        cluster_id: ClusterId,
        message: ClusterJoinMessage,
        global_state: &RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        // Ignore messages sent for a different cluster
        if cluster_id != *global_state.read_cluster_id() {
            return Ok(());
        }

        // Add the peer to the cluster metadata
        // Move out of message to avoid clones
        let peer_id = message.peer_id;
        let peer_info = message.peer_info;
        let peer_addr = message.addr;

        Self::add_peer_to_cluster(
            peer_id,
            peer_info,
            cluster_id.clone(),
            global_state,
            network_channel.clone(),
        )?;

        // Add the peer to the known peers index
        {
            global_state
                .write_peer_index()
                .add_peer(PeerInfo::new(peer_id, cluster_id, peer_addr));
        } // peer_index lock released

        // Request that the peer replicate all locally replicated wallets
        let wallets = global_state.read_wallet_index().get_all_wallets();
        Self::send_replicate_request(message.peer_id, wallets, network_channel)
    }

    /// Add a peer to the given cluster
    fn add_peer_to_cluster(
        peer_id: WrappedPeerId,
        peer_info: PeerInfo,
        cluster_id: ClusterId,
        global_state: &RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        // Ignore messages sent for a different cluster
        if cluster_id != *global_state.read_cluster_id() {
            return Ok(());
        }

        // Add the peer to the known peers index
        global_state.add_single_peer(peer_id, peer_info);

        // The cluster join request is authenticated at the network layer
        // by the `NetworkManager`, so no authentication needs to be done.
        // Simply update the local cluster metadata to reflect the new node's membership
        {
            let mut locked_cluster_metadata = global_state.write_cluster_metadata();
            locked_cluster_metadata.add_member(peer_id);
        } // locked_cluster_metadata released

        // Request that the peer replicate all locally replicated wallets
        let wallets = global_state.read_wallet_index().get_all_wallets();
        Self::send_replicate_request(peer_id, wallets, network_channel)
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
                message: GossipRequest::Replicate(ReplicateRequestBody { wallets }),
            })
            .map_err(|err| GossipError::SendMessage(err.to_string()))
    }

    /// Handles a request from a peer to replicate a given set of wallets
    fn handle_replicate_request(
        req: ReplicateRequestBody,
        global_state: &RelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Result<(), GossipError> {
        // Add wallets to global state
        {
            let mut wallets_locked = global_state.write_wallet_index();
            for wallet in req.wallets.iter() {
                wallets_locked.add_wallet(wallet.clone());
            }
        } // wallets_locked released

        // Broadcast a message to the network indicating that the wallet is now replicated
        let topic = global_state
            .read_cluster_metadata()
            .id
            .get_management_topic();
        let message = PubsubMessage::new_cluster_management_unsigned(
            global_state.read_cluster_id().clone(),
            ClusterManagementMessage::Replicated(ReplicatedMessage {
                wallets: req.wallets,
                peer_id: global_state.local_peer_id(),
            }),
        );

        network_channel
            .send(GossipOutbound::Pubsub { topic, message })
            .map_err(|err| GossipError::SendMessage(err.to_string()))?;

        Ok(())
    }

    /// Handles an incoming job to update a wallet's replicas with a newly added peer
    fn handle_add_replica_job(
        peer_id: WrappedPeerId,
        wallet_id: WalletIdentifier,
        global_state: &RelayerState,
    ) {
        global_state
            .read_wallet_index()
            .add_replica(&wallet_id, peer_id);
    }
}
