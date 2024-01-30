//! Handles bootstrap requests and responses

use gossip_api::request_response::{heartbeat::BootstrapRequest, GossipResponse};

use crate::{errors::GossipError, server::GossipProtocolExecutor};

impl GossipProtocolExecutor {
    /// Handles a bootstrap request from a peer    
    pub fn handle_bootstrap_req(
        &self,
        req: BootstrapRequest,
    ) -> Result<GossipResponse, GossipError> {
        // Add the peer to the index
        self.add_new_peers(vec![req.peer_info])?;
        let resp = self.build_heartbeat()?;

        Ok(GossipResponse::Heartbeat(resp))
    }
}
