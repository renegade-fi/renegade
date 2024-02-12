//! Handles bootstrap requests and responses

use common::types::gossip::{PeerInfo, WrappedPeerId};
use gossip_api::request_response::{
    heartbeat::{BootstrapRequest, PeerInfoResponse},
    GossipResponse,
};
use itertools::Itertools;
use job_types::network_manager::{NetworkManagerControlSignal, NetworkManagerJob};
use tracing::warn;
use util::{err_str, get_current_time_seconds};

use crate::{
    errors::GossipError, peer_discovery::heartbeat::EXPIRY_INVISIBILITY_WINDOW_MS,
    server::GossipProtocolExecutor,
};

impl GossipProtocolExecutor {
    // --------------------
    // | Inbound Requests |
    // --------------------

    /// Handles a request for peer info
    pub fn handle_peer_info_req(
        &self,
        peers: Vec<WrappedPeerId>,
    ) -> Result<GossipResponse, GossipError> {
        let peer_info = self.global_state.get_peer_info_map()?;

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
        let resp = self.build_heartbeat()?;

        Ok(GossipResponse::Heartbeat(resp))
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
        let now = get_current_time_seconds();
        let filtered_peers = {
            let mut locked_expiry_cache = self.peer_expiry_cache.write().await;
            peers
                .iter()
                .filter(|peer| {
                    // Check that the peer is not in its invisibility window
                    if let Some(expired_at) = locked_expiry_cache.get(&peer.peer_id) {
                        if now - *expired_at <= EXPIRY_INVISIBILITY_WINDOW_MS / 1000 {
                            return false;
                        }
                    }

                    // Check that the cluster auth signature on the peer is valid
                    if peer.verify_cluster_auth_sig().is_err() {
                        warn!("Peer {} info has invalid cluster auth signature", peer.peer_id);
                        return false;
                    }

                    // Remove the peer from the expiry cache if its invisibility window has
                    // elapsed
                    locked_expiry_cache.pop_entry(&peer.peer_id);
                    true
                })
                .cloned()
                .collect_vec()
        }; // locked_expiry_cache released

        // Add all filtered peers to the network manager's address table
        self.add_new_addrs(&filtered_peers)?;
        // Add all filtered peers to the global peer index
        self.global_state.add_peer_batch(filtered_peers)?;

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
