//! Defines handlers for the Identify protocol

use job_types::gossip_server::GossipServerJob;
use libp2p::identify::Event as IdentifyEvent;
use libp2p_core::multiaddr::Protocol;
use tracing::log;

use crate::{error::NetworkManagerError, manager::replace_port};

use super::NetworkManagerExecutor;

impl NetworkManagerExecutor {
    /// Handle a message from the Identify protocol
    pub(super) fn handle_identify_event(
        &mut self,
        event: IdentifyEvent,
    ) -> Result<(), NetworkManagerError> {
        // Update the local peer's public IP address if it has not already been
        // discovered
        if let IdentifyEvent::Received { info, .. } = event {
            if !self.discovered_identity {
                // Replace the port if the discovered NAT port is incorrect
                let mut local_addr = info.observed_addr;
                replace_port(&mut local_addr, self.p2p_port);

                // Add the p2p multihash to the multiaddr
                local_addr = local_addr.with(Protocol::P2p(self.local_peer_id.0.into()));

                // Update the addr in the global state
                log::info!("discovered local peer's public IP: {:?}", local_addr);
                self.global_state.update_local_peer_addr(&local_addr)?;
                self.discovered_identity = true;

                // Optimistically broadcast the discovered identity to the network via
                // the heartbeat sub-protocol
                for peer in self.global_state.get_all_peers_ids(false /* include_self */)? {
                    if let Err(e) =
                        self.gossip_work_queue.send(GossipServerJob::ExecuteHeartbeat(peer))
                    {
                        log::error!("error forwarding heartbeat to gossip server: {e}")
                    }
                }
            }
        }

        Ok(())
    }
}
