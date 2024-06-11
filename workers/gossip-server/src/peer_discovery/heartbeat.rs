//! Groups gossip server logic for the heartbeat protocol

use common::types::gossip::{PeerInfo, WrappedPeerId};
use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        PubsubMessage,
    },
    request_response::{
        heartbeat::{HeartbeatMessage, PeerInfoRequest},
        orderbook::OrderInfoRequest,
        GossipRequestType,
    },
};
use job_types::network_manager::{NetworkManagerControlSignal, NetworkManagerJob};
use renegade_metrics::helpers::record_num_peers_metrics;
use tracing::{info, instrument, warn};
use util::{err_str, get_current_time_millis};

use crate::{errors::GossipError, server::GossipProtocolExecutor};

// -------------
// | Constants |
// -------------

/// The interval at which to send heartbeats to non-cluster known peers
pub const HEARTBEAT_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The interval at which to send heartbeats to cluster peer
pub const CLUSTER_HEARTBEAT_INTERVAL_MS: u64 = 3_000; // 3 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for non-cluster peers
pub const HEARTBEAT_FAILURE_MS: u64 = 30_000; // 30 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for cluster peers
pub const CLUSTER_HEARTBEAT_FAILURE_MS: u64 = 15_000; // 15 seconds

// -----------
// | Helpers |
// -----------

/// Heartbeat implementation of the protocol executor
impl GossipProtocolExecutor {
    // ------------
    // | Outbound |
    // ------------

    /// Sends heartbeat message to peers to exchange network information and
    /// ensure liveness
    pub async fn send_heartbeat(
        &self,
        recipient_peer_id: WrappedPeerId,
    ) -> Result<(), GossipError> {
        if recipient_peer_id == self.config.local_peer_id {
            return Ok(());
        }

        let heartbeat_message = self.build_heartbeat().await?;
        let msg = GossipRequestType::Heartbeat(heartbeat_message);
        let job = NetworkManagerJob::request(recipient_peer_id, msg);

        self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
        self.update_expiry_status(recipient_peer_id).await
    }

    // ---------------------
    // | Inbound Heartbeat |
    // ---------------------

    /// Handle a heartbeat message from a peer
    #[instrument(skip_all, err, fields(peer = %peer))]
    pub async fn handle_heartbeat(
        &self,
        peer: &WrappedPeerId,
        message: &HeartbeatMessage,
    ) -> Result<(), GossipError> {
        info!("Received heartbeat from {peer}");
        if peer != &message.self_id {
            warn!(
                "Heartbeat peer mismatch. libp2p sender: {peer}, payload sender: {}",
                message.self_id
            );
        }

        // Record the heartbeat
        self.record_heartbeat(peer).await?;

        // If peer is an expiry candidate, remove it, & send expiry rejection to other
        // peers
        if self.expiry_buffer.is_expiry_candidate(peer).await {
            self.expiry_buffer.remove_expiry_candidate(*peer).await;
            if let Some(peer_info) = self.state.get_peer_info(peer).await? {
                self.send_expiry_rejection(*peer, peer_info.last_heartbeat).await?;
            }
        }

        // Merge the peer and order info from the heartbeat into the local state
        self.request_missing_orders(peer, message).await?;
        self.request_missing_peers(peer, message).await
    }

    /// Request any missing orders in the heartbeat message from the given peer
    async fn request_missing_orders(
        &self,
        peer: &WrappedPeerId,
        message: &HeartbeatMessage,
    ) -> Result<(), GossipError> {
        let missing_orders = self.state.get_missing_orders(&message.known_orders).await?;
        let req = GossipRequestType::OrderInfo(OrderInfoRequest { order_ids: missing_orders });
        self.network_channel
            .send(NetworkManagerJob::request(*peer, req))
            .map_err(err_str!(GossipError::SendMessage))
    }

    /// Request any missing peer info from the given peer
    async fn request_missing_peers(
        &self,
        peer: &WrappedPeerId,
        message: &HeartbeatMessage,
    ) -> Result<(), GossipError> {
        let missing_peers = self.state.get_missing_peers(&message.known_peers).await?;
        let req = GossipRequestType::PeerInfo(PeerInfoRequest { peer_ids: missing_peers });
        self.network_channel
            .send(NetworkManagerJob::request(*peer, req))
            .map_err(err_str!(GossipError::SendMessage))
    }

    // -----------
    // | Helpers |
    // -----------

    // --- Heartbeat --- //

    /// Records a successful heartbeat
    pub(super) async fn record_heartbeat(
        &self,
        peer_id: &WrappedPeerId,
    ) -> Result<(), GossipError> {
        Ok(self.state.record_heartbeat(peer_id).await?)
    }

    /// Build a heartbeat message
    pub async fn build_heartbeat(&self) -> Result<HeartbeatMessage, GossipError> {
        let expiry_candidates = self.expiry_buffer.get_candidates().await;
        Ok(self.state.construct_heartbeat(expiry_candidates).await?)
    }

    // --- Peer Expiry --- //

    /// Update the expiry status of a peer
    async fn update_expiry_status(&self, peer_id: WrappedPeerId) -> Result<(), GossipError> {
        if self.expiry_buffer.is_expiry_candidate(&peer_id).await {
            self.maybe_expire_candidate(peer_id).await
        } else {
            self.maybe_expire_peer(peer_id).await
        }
    }

    /// Expires peers that have timed out due to consecutive failed heartbeats
    async fn maybe_expire_peer(&self, peer_id: WrappedPeerId) -> Result<(), GossipError> {
        // Find the peer's info in global state
        let maybe_info = self.state.get_peer_info(&peer_id).await?;
        let peer_info = match maybe_info {
            Some(info) => info,
            None => {
                info!("could not find info for peer {peer_id:?}");
                return Ok(());
            },
        };

        // Check whether the expiry window has elapsed
        if !self.should_expire_peer(&peer_info).await? {
            return Ok(());
        }

        // If the node is outside the cluster expire it immediately
        let cluster_id = self.state.get_cluster_id().await?;
        let same_cluster = peer_info.get_cluster_id() == cluster_id;
        if !same_cluster {
            return self.expire_peer(peer_id).await;
        }

        // Otherwise transition the node to an expiry candidate state
        // and notify cluster peers
        info!("proposing expiry of peer: {peer_id}");
        self.expiry_buffer.mark_expiry_candidate(peer_id).await;
        let msg = ClusterManagementMessage {
            cluster_id: cluster_id.clone(),
            message_type: ClusterManagementMessageType::ProposeExpiry(peer_id),
        };

        let topic = cluster_id.get_management_topic();
        let job = NetworkManagerJob::pubsub(topic, PubsubMessage::Cluster(msg));
        self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))
    }

    /// Check whether the expiry window for a peer has elapsed
    async fn should_expire_peer(&self, peer_info: &PeerInfo) -> Result<bool, GossipError> {
        // Expire cluster peers sooner than non-cluster peers
        let cluster_id = self.state.get_cluster_id().await?;
        let same_cluster = peer_info.get_cluster_id() == cluster_id;

        let now = get_current_time_millis();
        let last_heartbeat = now - peer_info.get_last_heartbeat();

        #[allow(clippy::if_same_then_else)]
        if same_cluster && last_heartbeat < CLUSTER_HEARTBEAT_FAILURE_MS {
            Ok(false)
        } else if !same_cluster && last_heartbeat < HEARTBEAT_FAILURE_MS {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Expire a peer that is already an expiry candidate if the attestation
    /// window has elapsed
    async fn maybe_expire_candidate(&self, peer: WrappedPeerId) -> Result<(), GossipError> {
        if self.expiry_buffer.should_expire(&peer).await {
            // Remove from the expiry candidates list
            self.expiry_buffer.remove_expiry_candidate(peer).await;
            return self.expire_peer(peer).await;
        }

        Ok(())
    }

    /// Expire a peer
    async fn expire_peer(&self, peer_id: WrappedPeerId) -> Result<(), GossipError> {
        // Remove expired peer from global state & DHT
        info!("Expiring peer {peer_id}");
        self.state.remove_peer(peer_id).await?;
        self.network_channel
            .send(NetworkManagerJob::internal(NetworkManagerControlSignal::PeerExpired { peer_id }))
            .map_err(err_str!(GossipError::SendMessage))?;

        // Add peers to expiry cache for the duration of their invisibility window. This
        // ensures that we do not add the expired peer back to the global state
        // until some time has elapsed. Without this check, another peer may
        // send us a heartbeat attesting to the expired peer's liveness,
        // having itself not expired the peer locally.
        self.expiry_buffer.mark_expired(peer_id).await;
        record_num_peers_metrics(&self.state).await;
        Ok(())
    }
}
