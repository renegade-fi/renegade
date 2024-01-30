//! Groups gossip server logic for the heartbeat protocol

use std::{collections::HashMap, thread, time::Duration};

use common::types::gossip::{PeerInfo, WrappedPeerId};
use futures::executor::block_on;
use gossip_api::request_response::{heartbeat::HeartbeatMessage, GossipRequest};
use job_types::{gossip_server::GossipServerJob, network_manager::NetworkManagerJob};
use state::State;
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tracing::log;
use util::{err_str, get_current_time_seconds};

use crate::{errors::GossipError, server::GossipProtocolExecutor};

// -------------
// | Constants |
// -------------

/// Nanoseconds in a millisecond, as an unsigned 64bit integer
pub(super) const NANOS_PER_MILLI: u64 = 1_000_000;
/// The interval at which to send heartbeats to non-cluster known peers
pub(super) const HEARTBEAT_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The interval at which to send heartbeats to cluster peer
pub(super) const CLUSTER_HEARTBEAT_INTERVAL_MS: u64 = 3_000; // 3 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for non-cluster peers
pub(super) const HEARTBEAT_FAILURE_MS: u64 = 20_000; // 20 seconds
/// The amount of time without a successful heartbeat before the local
/// relayer should assume its peer has failed; for cluster peers
pub(super) const CLUSTER_HEARTBEAT_FAILURE_MS: u64 = 7_000; // 7 seconds
/// The minimum amount of time between a peer's expiry and when it can be
/// added back to the peer info
#[allow(unused)]
pub(super) const EXPIRY_INVISIBILITY_WINDOW_MS: u64 = 30_000; // 30 seconds
/// The size of the peer expiry cache to keep around
pub(super) const EXPIRY_CACHE_SIZE: usize = 100;

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

        // Merge the peer info from the heartbeat into the local state
        self.merge_state_from_message(message)?;

        Ok(())
    }

    /// Sync the replication state when a heartbeat is received
    /// Effectively:
    ///  For each wallet that the local relayer manages:
    ///      1. Check if the peer sent a replication list for this wallet
    ///      2. Add any new peers from that list to the local state
    /// TODO: There is probably a cleaner way to do this
    pub(super) fn merge_state_from_message(
        &self,
        message: HeartbeatMessage,
    ) -> Result<(), GossipError> {
        let mut peers_to_add = Vec::new();
        let state = &self.global_state;
        for (peer_id, info) in message.known_peers.into_iter() {
            if state.get_peer_info(&peer_id)?.is_some() {
                peers_to_add.push(info);
            }
        }

        self.add_new_peers(peers_to_add).await
    }

    /// Index a new peer if:
    ///     1. The peer is not already in the known peers
    ///     2. The peer has not been recently expired by the local party
    /// The second condition is necessary because if we expire a peer, the party
    /// sending a heartbeat may not have expired the faulty peer yet, and may
    /// still send the faulty peer as a known peer. So we exclude
    /// thought-to-be-faulty peers for an "invisibility window"
    ///
    /// Returns a boolean indicating whether the peer is now indexed in the peer
    /// info state. This value may be false if the peer has been recently
    /// expired and its invisibility window has not elapsed
    pub(super) fn add_new_peers(&self, _peers: Vec<PeerInfo>) -> Result<(), GossipError> {
        todo!("implement this with gossip refactor");
        // // Filter out peers that are in their expiry window
        // // or those that are missing peer info
        // let now = get_current_time_seconds();
        // let filtered_peers = {
        //     let mut locked_expiry_cache =
        // self.peer_expiry_cache.write().await;

        //     new_peer_ids
        //         .iter()
        //         .filter(|peer_id| {
        //             if let Some(expired_at) =
        // locked_expiry_cache.get(*peer_id) {                 if now -
        // *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS / 1000 {
        // return false;                 }

        //                 // Remove the peer from the expiry cache if its
        // invisibility window has                 // elapsed
        //                 locked_expiry_cache.pop_entry(*peer_id);
        //             }

        //             // Filter out the peer if the message including it did
        // not attach peer info
        // new_peer_info.contains_key(*peer_id)         })
        //         .cloned()
        //         .collect_vec()
        // }; // locked_expiry_cache released

        // // Add all filtered peers to the network manager's address table
        // self.add_new_addrs(&filtered_peers, new_peer_info)?;
        // // Add all filtered peers to the global peer index
        // self.global_state.add_peer_batch(&new_peer_info)?.await?;

        // Ok(true)
    }

    /// Adds new addresses to the address index in the network manager so that
    /// they may be dialed on outbound
    #[allow(unused)]
    fn add_new_addrs(
        &self,
        peer_ids: &[WrappedPeerId],
        peer_info: &HashMap<WrappedPeerId, PeerInfo>,
    ) -> Result<(), GossipError> {
        for peer in peer_ids.iter() {
            self.network_channel
                .send(GossipOutbound::ManagementMessage(ManagerControlDirective::NewAddr {
                    peer_id: *peer,
                    address: peer_info.get(peer).unwrap().get_addr(),
                }))
                .map_err(|err| GossipError::SendMessage(err.to_string()))?;
        }

        Ok(())
    }

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

        log::info!("Expiring peer");

        // Remove expired peers from global state
        self.global_state.remove_peer(peer_id)?.await?;

        // Add peers to expiry cache for the duration of their invisibility window. This
        // ensures that we do not add the expired peer back to the global state
        // until some time has elapsed. Without this check, another peer may
        // send us a heartbeat attesting to the expired peer's liveness,
        // having itself not expired the peer locally.
        let mut locked_expiry_cache = self.peer_expiry_cache.write().await;
        locked_expiry_cache.put(peer_id, now);

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Records a successful heartbeat
    pub(super) fn record_heartbeat(&self, peer_id: &WrappedPeerId) -> Result<(), GossipError> {
        Ok(self.global_state.record_heartbeat(peer_id)?)
    }

    /// Build a heartbeat message
    pub fn build_heartbeat(&self) -> Result<HeartbeatMessage, GossipError> {
        Ok(self.global_state.construct_heartbeat()?)
    }
}
