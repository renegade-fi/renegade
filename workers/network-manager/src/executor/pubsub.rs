//! Defines pubsub message handlers

use std::sync::atomic::Ordering;

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        AuthenticatedPubsubMessage, PubsubMessage,
    },
    GossipDestination,
};
use job_types::{gossip_server::GossipServerJob, handshake_manager::HandshakeManagerJob};
use libp2p::gossipsub::{Message as GossipsubMessage, Sha256Topic};
use util::err_str;

use crate::error::NetworkManagerError;

use super::{behavior::BehaviorJob, BufferedPubsubMessage, NetworkManagerExecutor};

/// Error emitted when a sender is missing from a pubsub message
const ERR_MISSING_SENDER: &str = "missing sender in pubsub message";

impl NetworkManagerExecutor {
    /// Forward an outbound pubsub message to the network
    pub(super) async fn forward_outbound_pubsub(
        &self,
        topic: String,
        message: PubsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // If the gossip server has not warmed up the local node into the network,
        // buffer the pubsub message for forwarding after the warmup
        if !self.warmup_finished.load(Ordering::Relaxed) {
            let mut buf = self.warmup_buffer.write().await;
            buf.push(BufferedPubsubMessage { topic, message });
            return Ok(());
        }

        // If we require a signature on the message attach one
        let key = self.cluster_key;
        let req_body = tokio::task::spawn_blocking(move || {
            AuthenticatedPubsubMessage::new_with_body(message, &key)
        })
        .await
        .unwrap();

        let topic = Sha256Topic::new(topic);
        self.send_behavior(BehaviorJob::SendPubsub(topic, req_body))
    }

    /// Handle an incoming network request for a pubsub message
    pub(super) async fn handle_inbound_pubsub_message(
        &self,
        message: GossipsubMessage,
    ) -> Result<(), NetworkManagerError> {
        // Deserialize into API types and verify auth
        let pkey = self.cluster_key;
        let event: AuthenticatedPubsubMessage =
            message.data.try_into().map_err(NetworkManagerError::Serialization)?;

        // Block on verification to avoid blocking the async pool
        let event = tokio::task::spawn_blocking(move || {
            event
                .verify_cluster_auth(&pkey)
                .then_some(event)
                .ok_or_else(NetworkManagerError::hmac_error)
        })
        .await
        .unwrap()?;

        let sender = message
            .source
            .map(WrappedPeerId)
            .ok_or_else(|| NetworkManagerError::UnhandledRequest(ERR_MISSING_SENDER.to_string()))?;

        match event.body.destination() {
            GossipDestination::GossipServer => self
                .gossip_work_queue
                .send(GossipServerJob::Pubsub(sender, event.body))
                .map_err(err_str!(NetworkManagerError::EnqueueJob)),

            GossipDestination::HandshakeManager => match event.body {
                PubsubMessage::Cluster(ClusterManagementMessage { message_type, .. }) => {
                    match message_type {
                        ClusterManagementMessageType::CacheSync(order1, order2) => self
                            .handshake_work_queue
                            .send(HandshakeManagerJob::CacheEntry { order1, order2 })
                            .map_err(err_str!(NetworkManagerError::EnqueueJob)),
                        ClusterManagementMessageType::MatchInProgress(order1, order2) => self
                            .handshake_work_queue
                            .send(HandshakeManagerJob::PeerMatchInProgress { order1, order2 })
                            .map_err(err_str!(NetworkManagerError::EnqueueJob)),
                        _ => unreachable!("handshake manager should not receive other messages"),
                    }
                },
                _ => unreachable!("handshake manager should not receive other messages"),
            },

            GossipDestination::NetworkManager => {
                unreachable!("network manager should not receive pubsub messages")
            },
        }
    }
}
