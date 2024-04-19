//! Defines pubsub message handlers

use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        AuthenticatedPubsubMessage, PubsubMessage,
    },
    GossipDestination,
};
use job_types::{gossip_server::GossipServerJob, handshake_manager::HandshakeExecutionJob};
use libp2p::gossipsub::{Message as GossipsubMessage, Sha256Topic};
use util::err_str;

use crate::error::NetworkManagerError;

use super::{BufferedPubsubMessage, NetworkManagerExecutor};

impl NetworkManagerExecutor {
    /// Forward an outbound pubsub message to the network
    pub(super) fn forward_outbound_pubsub(
        &mut self,
        topic: String,
        message: PubsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // If the gossip server has not warmed up the local node into the network,
        // buffer the pubsub message for forwarding after the warmup
        if !self.warmup_finished {
            self.warmup_buffer.push(BufferedPubsubMessage { topic, message });
            return Ok(());
        }

        // If we require a signature on the message attach one
        let req_body = AuthenticatedPubsubMessage::new_with_body(message, &self.cluster_key)?;

        // Forward to the network
        let topic = Sha256Topic::new(topic);
        self.swarm
            .behaviour_mut()
            .pubsub
            .publish(topic, req_body)
            .map_err(|err| NetworkManagerError::Network(err.to_string()))?;
        Ok(())
    }

    /// Handle an incoming network request for a pubsub message
    pub(super) fn handle_inbound_pubsub_message(
        &mut self,
        message: GossipsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // Deserialize into API types and verify auth
        let event: AuthenticatedPubsubMessage =
            message.data.try_into().map_err(NetworkManagerError::Serialization)?;
        event.verify_cluster_auth(&self.cluster_key.public)?;

        match event.body.destination() {
            GossipDestination::GossipServer => self
                .gossip_work_queue
                .send(GossipServerJob::Pubsub(event.body))
                .map_err(err_str!(NetworkManagerError::EnqueueJob)),

            GossipDestination::HandshakeManager => match event.body {
                PubsubMessage::Cluster(ClusterManagementMessage { message_type, .. }) => {
                    match message_type {
                        ClusterManagementMessageType::CacheSync(order1, order2) => self
                            .handshake_work_queue
                            .send(HandshakeExecutionJob::CacheEntry { order1, order2 })
                            .map_err(err_str!(NetworkManagerError::EnqueueJob)),
                        ClusterManagementMessageType::MatchInProgress(order1, order2) => self
                            .handshake_work_queue
                            .send(HandshakeExecutionJob::PeerMatchInProgress { order1, order2 })
                            .map_err(err_str!(NetworkManagerError::EnqueueJob)),
                    }
                },
                PubsubMessage::Orderbook(_) => {
                    unreachable!("handshake manager should not receive orderbook messages")
                },
            },

            GossipDestination::NetworkManager => {
                unreachable!("network manager should not receive pubsub messages")
            },
        }
    }
}
