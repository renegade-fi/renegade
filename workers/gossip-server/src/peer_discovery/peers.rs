//! Handles bootstrap requests and responses

use common::types::gossip::{PeerInfo, WrappedPeerId};
use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        PubsubMessage,
    },
    request_response::{
        heartbeat::{BootstrapRequest, PeerInfoResponse},
        GossipResponse,
    },
};
use job_types::network_manager::{NetworkManagerControlSignal, NetworkManagerJob};
use renegade_metrics::helpers::record_num_peers_metrics;
use tracing::{info, warn};
use util::{err_str, get_current_time_millis};

use crate::{errors::GossipError, server::GossipProtocolExecutor};

use super::heartbeat::CLUSTER_HEARTBEAT_FAILURE_MS;

impl GossipProtocolExecutor {
    // --------------------
    // | Inbound Requests |
    // --------------------

    /// Handles a request for peer info
    pub async fn handle_peer_info_req(
        &self,
        peers: Vec<WrappedPeerId>,
    ) -> Result<GossipResponse, GossipError> {
        let peer_info = self.state.get_peer_info_map().await?;

        let mut res = Vec::new();
        for peer in peers {
            if let Some(info) = peer_info.get(&peer) {
                res.push(info.clone());
            }
        }

        let resp = GossipResponse::PeerInfo(PeerInfoResponse { peer_info: res });
        Ok(resp)
    }

    /// Handles a bootstrap request from a peer    
    pub async fn handle_bootstrap_req(
        &self,
        req: BootstrapRequest,
    ) -> Result<GossipResponse, GossipError> {
        // Add the peer to the index
        self.add_new_peers(vec![req.peer_info]).await?;
        let resp = self.build_heartbeat().await?;

        Ok(GossipResponse::Heartbeat(resp))
    }

    /// Handle a proposed expiry from a peer
    ///
    /// TODO: Update this logic, for now we simply check if the local peer
    /// thinks the expiry candidate should expire
    pub async fn handle_propose_expiry(
        &self,
        sender: WrappedPeerId,
        peer_id: WrappedPeerId,
    ) -> Result<(), GossipError> {
        let peer_info = self.state.get_peer_info(&peer_id).await?;
        let info = match peer_info {
            Some(info) => info,
            None => return Ok(()),
        };

        // If the local peer has received a recent heartbeat from the candidate, notify
        // the sender that the expiry should not proceed
        let now = get_current_time_millis();
        let time_since_last_heartbeat = now - info.last_heartbeat;
        if time_since_last_heartbeat < CLUSTER_HEARTBEAT_FAILURE_MS / 2 {
            info!("rejecting expiry of {peer_id} from {sender}, last heartbeat was {time_since_last_heartbeat}ms ago");

            // The peer should not expire yet, send a rejection
            let cluster_id = self.state.get_cluster_id().await?;
            let topic = cluster_id.get_management_topic();
            let message_type = ClusterManagementMessageType::RejectExpiry {
                peer_id,
                last_heartbeat: info.last_heartbeat,
            };

            let msg = PubsubMessage::Cluster(ClusterManagementMessage { cluster_id, message_type });
            let job = NetworkManagerJob::pubsub(topic, msg);
            self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
        } else {
            // If we do not reject the expiry, begin expiring on the local node
            info!("received expiry request, marking {peer_id} as expiry candidate");
            self.expiry_buffer.mark_expiry_candidate(peer_id).await;
        }

        Ok(())
    }

    /// Handle a request to reject expiry
    pub async fn handle_reject_expiry(
        &self,
        peer_id: WrappedPeerId,
        last_heartbeat: u64,
    ) -> Result<(), GossipError> {
        info!("received reject expiry request");
        // Remove from the expiry buffer if present
        self.expiry_buffer.remove_expiry_candidate(peer_id).await;

        // Update the latest heartbeat for the peer
        let maybe_info = self.state.get_peer_info(&peer_id).await?;
        let mut info = match maybe_info {
            Some(info) => info,
            None => return Ok(()),
        };

        if info.last_heartbeat < last_heartbeat {
            info.last_heartbeat = last_heartbeat;
            self.state.set_peer_info(info).await?;
        }

        Ok(())
    }

    // ---------------------
    // | Inbound Responses |
    // ---------------------

    /// Handles a response to a request for peer info
    pub async fn handle_peer_info_resp(&self, peer_info: Vec<PeerInfo>) -> Result<(), GossipError> {
        self.add_new_peers(peer_info).await
    }

    // -----------
    // | Helpers |
    // -----------

    /// Index a new peer if the peer has not been recently expired by the local
    /// party. This is necessary because if we expire a peer, the party sending
    /// a heartbeat may not have expired the faulty peer yet, and may still
    /// send the faulty peer as a known peer. So we
    /// exclude thought-to-be-faulty peers for an "invisibility window"
    async fn add_new_peers(&self, peers: Vec<PeerInfo>) -> Result<(), GossipError> {
        if peers.is_empty() {
            return Ok(());
        }

        // Filter out peers that are in their expiry window
        let mut filtered_peers = Vec::new();
        for peer in peers.into_iter() {
            // Check that the peer is not in its invisibility window
            if self.expiry_buffer.is_invisible(&peer.peer_id).await {
                continue;
            }

            // Check that the cluster auth signature on the peer is valid
            if peer.verify_cluster_auth_sig().is_err() {
                warn!("Peer {} info has invalid cluster auth signature", peer.peer_id);
                continue;
            }

            filtered_peers.push(peer);
        }

        // Add all filtered peers to the network manager's address table
        self.add_new_addrs(&filtered_peers)?;
        // Add all filtered peers to the global peer index
        self.state.add_peer_batch(filtered_peers.clone()).await?;

        record_num_peers_metrics(&self.state).await;

        Ok(())
    }

    /// Adds new addresses to the address index in the network manager so that
    /// they may be dialed on outbound
    fn add_new_addrs(&self, peers: &[PeerInfo]) -> Result<(), GossipError> {
        for peer in peers.iter() {
            let job = NetworkManagerJob::internal(NetworkManagerControlSignal::NewAddr {
                peer_id: peer.peer_id,
                address: peer.get_addr(),
            });

            self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
        }

        Ok(())
    }
}
