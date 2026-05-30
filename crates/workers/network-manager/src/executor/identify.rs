//! Defines handlers for the Identify protocol

use std::sync::atomic::Ordering;

use job_types::gossip_server::GossipServerJob;
use libp2p::identify::Event as IdentifyEvent;
use libp2p_core::multiaddr::Protocol;
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
use crate::{error::NetworkManagerError, executor::replace_port};

use super::NetworkManagerExecutor;

impl NetworkManagerExecutor {
    /// Handle a message from the Identify protocol
    pub async fn handle_identify_event(
        &self,
        event: IdentifyEvent,
    ) -> Result<(), NetworkManagerError> {
        // Update the local peer's public IP address if it has not already been
        // discovered
        if let IdentifyEvent::Received { info, .. } = event
            && !self.discovered_identity.load(Ordering::Relaxed)
        {
            // Replace the port if the discovered NAT port is incorrect
            let mut local_addr = info.observed_addr;
            replace_port(&mut local_addr, self.p2p_port);

            // Add the p2p multihash to the multiaddr
            local_addr = local_addr.with(Protocol::P2p(self.local_peer_id.0.into()));

            // Update the addr in the global state
            log_task!(Task::Identify, Outcome::Ok, subject = ?local_addr, "discovered local peer's public IP");
            self.global_state.update_local_peer_addr(local_addr).await?;
            self.discovered_identity.store(true, Ordering::Relaxed);

            // Optimistically broadcast the discovered identity to the network via
            // the heartbeat sub-protocol
            for peer in self.global_state.get_all_peers_ids(false /* include_self */).await? {
                if let Err(e) = self.gossip_work_queue.send(GossipServerJob::ExecuteHeartbeat(peer))
                {
                    log_task!(Task::ForwardHeartbeat, Outcome::Failed, subject = %peer, error = %e, "error forwarding heartbeat to gossip server")
                }
            }
        }

        Ok(())
    }
}
