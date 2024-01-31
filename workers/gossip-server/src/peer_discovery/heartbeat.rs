//! Groups gossip server logic for the heartbeat protocol

use common::types::gossip::WrappedPeerId;
use gossip_api::request_response::{
    heartbeat::{HeartbeatMessage, PeerInfoRequest},
    orderbook::OrderInfoRequest,
    GossipRequest,
};
use job_types::network_manager::NetworkManagerJob;
use tracing::log;
use util::{err_str, get_current_time_seconds};

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
pub const HEARTBEAT_FAILURE_MS: u64 = 20_000; // 20 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for cluster peers
pub const CLUSTER_HEARTBEAT_FAILURE_MS: u64 = 7_000; // 7 seconds
/// The minimum amount of time between a peer's expiry and when it can be
/// added back to the peer info
pub(crate) const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 30_000; // 30 seconds
/// The size of the peer expiry cache to keep around
pub(crate) const EXPIRY_CACHE_SIZE: usize = 100;

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

        let heartbeat_message = self.global_state.construct_heartbeat()?;
        let msg = GossipRequest::Heartbeat(heartbeat_message);
        let job = NetworkManagerJob::Request(recipient_peer_id, msg);

        self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
        self.maybe_expire_peer(recipient_peer_id).await
    }

    // ---------------------
    // | Inbound Heartbeat |
    // ---------------------

    /// Handle a heartbeat message from a peer
    pub fn handle_heartbeat(
        &self,
        peer: &WrappedPeerId,
        message: HeartbeatMessage,
    ) -> Result<(), GossipError> {
        // Record the heartbeat
        self.record_heartbeat(peer)?;

        // Merge the peer and order info from the heartbeat into the local state
        self.request_missing_orders(peer, &message)?;
        self.request_missing_peers(peer, &message)
    }

    /// Request any missing orders in the heartbeat message from the given peer
    fn request_missing_orders(
        &self,
        peer: &WrappedPeerId,
        message: &HeartbeatMessage,
    ) -> Result<(), GossipError> {
        let missing_orders = self.global_state.get_missing_orders(&message.known_orders)?;
        let req = GossipRequest::OrderInfo(OrderInfoRequest { order_ids: missing_orders });
        self.network_channel
            .send(NetworkManagerJob::Request(*peer, req))
            .map_err(err_str!(GossipError::SendMessage))
    }

    /// Request any missing peer info from the given peer
    fn request_missing_peers(
        &self,
        peer: &WrappedPeerId,
        message: &HeartbeatMessage,
    ) -> Result<(), GossipError> {
        let missing_peers = self.global_state.get_missing_peers(&message.known_peers)?;
        let req = GossipRequest::PeerInfo(PeerInfoRequest { peer_ids: missing_peers });
        self.network_channel
            .send(NetworkManagerJob::Request(*peer, req))
            .map_err(err_str!(GossipError::SendMessage))
    }

    // -----------
    // | Helpers |
    // -----------

    /// Expires peers that have timed out due to consecutive failed heartbeats
    async fn maybe_expire_peer(&self, peer_id: WrappedPeerId) -> Result<(), GossipError> {
        // Find the peer's info in global state
        let peer_info = self.global_state.get_peer_info(&peer_id)?;
        if peer_info.is_none() {
            log::info!("could not find info for peer {peer_id:?}");
            return Ok(());
        }
        let peer_info = peer_info.unwrap();

        // Expire cluster peers sooner than non-cluster peers
        let cluster_id = self.global_state.get_cluster_id()?;
        let same_cluster = peer_info.get_cluster_id() == cluster_id;

        let now = get_current_time_seconds();
        let last_heartbeat = now - peer_info.get_last_heartbeat();

        #[allow(clippy::if_same_then_else)]
        if same_cluster && last_heartbeat < CLUSTER_HEARTBEAT_FAILURE_MS / 1000 {
            return Ok(());
        } else if !same_cluster && last_heartbeat < HEARTBEAT_FAILURE_MS / 1000 {
            return Ok(());
        }

        // Remove expired peers from global state
        log::info!("Expiring peer {peer_id}");
        self.global_state.remove_peer(peer_id)?;

        // Add peers to expiry cache for the duration of their invisibility window. This
        // ensures that we do not add the expired peer back to the global state
        // until some time has elapsed. Without this check, another peer may
        // send us a heartbeat attesting to the expired peer's liveness,
        // having itself not expired the peer locally.
        let mut locked_expiry_cache = self.peer_expiry_cache.write().await;
        locked_expiry_cache.put(peer_id, now);

        Ok(())
    }

    /// Records a successful heartbeat
    pub(super) fn record_heartbeat(&self, peer_id: &WrappedPeerId) -> Result<(), GossipError> {
        Ok(self.global_state.record_heartbeat(peer_id)?)
    }

    /// Build a heartbeat message
    pub fn build_heartbeat(&self) -> Result<HeartbeatMessage, GossipError> {
        Ok(self.global_state.construct_heartbeat()?)
    }
}
