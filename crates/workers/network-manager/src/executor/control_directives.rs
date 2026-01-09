//! Defines handlers for network manager control directives, which are messages
//! that correspond to some action in the NetworkManager itself

use std::sync::atomic::Ordering;

use itertools::Itertools;
use job_types::network_manager::NetworkManagerControlSignal;
use libp2p::PeerId;
use libp2p_core::Multiaddr;
use tracing::info;
use util::networking::is_dialable_multiaddr;

use crate::error::NetworkManagerError;

use super::{NetworkManagerExecutor, behavior::BehaviorJob};

impl NetworkManagerExecutor {
    /// Handles a message from another worker module that explicitly directs the
    /// network manager to take some action
    ///
    /// The end destination of these messages is not a network peer, but the
    /// local network manager itself
    pub(super) async fn handle_control_directive(
        &self,
        command: NetworkManagerControlSignal,
    ) -> Result<(), NetworkManagerError> {
        match command {
            // Register a new peer in the distributed routing tables
            NetworkManagerControlSignal::NewAddr { peer_id, address } => {
                self.handle_new_addr(peer_id.inner(), address)?;
                Ok(())
            },

            // Remove a peer from the distributed routing tables
            NetworkManagerControlSignal::PeerExpired { peer_id } => {
                self.handle_peer_expired(&peer_id.inner())?;
                Ok(())
            },

            // Inform the network manager that the gossip server has warmed up the local node in
            // the cluster by advertising the local node's presence
            //
            // The network manager delays sending pubsub events until the gossip protocol has warmed
            // up, because at startup, there are no known peers to publish to. The network manager
            // gives the gossip server some time to discover new addresses before
            // publishing to the network.
            NetworkManagerControlSignal::GossipWarmupComplete => {
                self.handle_gossip_warmup_complete().await
            },
        }
    }

    /// Handle a new address added to the peer index
    fn handle_new_addr(&self, peer_id: PeerId, addr: Multiaddr) -> Result<(), NetworkManagerError> {
        // If we cannot parse the address or it is not dialable, skip indexing
        if !is_dialable_multiaddr(&addr, self.allow_local) {
            info!("skipping local addr {addr:?}");
            return Ok(());
        }

        self.send_behavior(BehaviorJob::AddAddress(peer_id, addr))
    }

    /// Handle removing a peer from the DHT
    fn handle_peer_expired(&self, peer_id: &PeerId) -> Result<(), NetworkManagerError> {
        self.send_behavior(BehaviorJob::RemovePeer(*peer_id))
    }

    /// Handle a complete gossip warmup
    async fn handle_gossip_warmup_complete(&self) -> Result<(), NetworkManagerError> {
        self.warmup_finished.store(true, Ordering::Relaxed);
        // Forward all buffered messages to the network
        let mut buf = self.warmup_buffer.write().await;
        for buffered_message in buf.drain(..).collect_vec() {
            self.forward_outbound_pubsub(buffered_message.topic, buffered_message.message).await?;
        }

        Ok(())
    }
}
