//! The gossip server manages the general gossip network interaction of a single p2p node

use std::{thread, time::Duration};

use ed25519_dalek::{Digest, Sha512};

use crate::api::{
    cluster_management::{ClusterJoinMessage, CLUSTER_JOIN_CHALLENGE_DIGEST},
    gossip::{GossipOutbound, PubsubMessage},
};

use super::{
    errors::GossipError, heartbeat_executor::HeartbeatProtocolExecutor, worker::GossipServerConfig,
};

/// The amount of time to wait for the node to find peers before sending
/// pubsub messages associated with setup
const PUBSUB_WARMUP_TIME_MS: u64 = 5_000; // 5 seconds

/// The server type that manages interactions with the gossip network
#[derive(Debug)]
pub struct GossipServer {
    /// The config for the Gossip Server
    pub(super) config: GossipServerConfig,
    /// The heartbeat executor, handles request/response for heartbeats
    pub(super) heartbeat_executor: Option<HeartbeatProtocolExecutor>,
}

impl GossipServer {
    /// Waits for the local node to warm up in the network (build up
    /// a graph of a few peers), and then publish an event to join the
    /// local cluster
    pub(super) fn warmup_then_join_cluster(&self) {
        // Copy items so they may be moved into the spawned threadd
        let cluster_id_copy = self.config.cluster_id.clone();
        let peer_id_copy = self.config.local_peer_id;
        let network_sender_copy = self.config.network_sender.clone();
        let cluster_management_topic = self.config.cluster_id.get_management_topic();

        // Sign the challenge message, this is used by recipients to validate that
        // the local party is authorized to join the target cluster
        // Hash the message
        // TODO: This signature should include the full message, including peerID so that it cannot
        // be spoofed
        let mut hash_digest: Sha512 = Sha512::new();
        hash_digest.update(CLUSTER_JOIN_CHALLENGE_DIGEST);

        // Sign and verify with keypair
        let sig = self
            .config
            .cluster_keypair
            .sign_prehashed(hash_digest, None /* context */)
            .unwrap();

        // Spawn a thread that will wait some time until the peer has warmed up into the network
        // and then emit a pubsub
        thread::spawn(move || {
            // Wait for the network to warmup
            thread::sleep(Duration::from_millis(PUBSUB_WARMUP_TIME_MS));

            // Send a message to the known peers that indiciates the local peer is joining its cluster
            let join_message = GossipOutbound::Pubsub {
                topic: cluster_management_topic,
                message: PubsubMessage::Join(ClusterJoinMessage {
                    cluster_id: cluster_id_copy,
                    node_id: peer_id_copy,
                    auth_challenge: sig.to_bytes().to_vec(),
                }),
            };
            network_sender_copy
                .send(join_message)
                .map_err(|err| GossipError::ServerSetupError(err.to_string()))
                .unwrap();
        });
    }
}
