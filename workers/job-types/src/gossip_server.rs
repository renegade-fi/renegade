//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    pubsub::PubsubMessage,
    request_response::{AuthenticatedGossipResponse, GossipRequest, GossipResponse},
};
use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender,
};

/// The queue sender type to send jobs to the gossip server
pub type GossipServerQueue = TokioSender<GossipServerJob>;
/// The queue receiver type to receive jobs from the gossip server
pub type GossipServerReceiver = TokioReceiver<GossipServerJob>;

/// Create a new gossip server queue and receiver
pub fn new_gossip_server_queue() -> (GossipServerQueue, GossipServerReceiver) {
    unbounded_channel()
}

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
#[derive(Debug)]
pub enum GossipServerJob {
    /// Execute a heartbeat to a given peer
    ExecuteHeartbeat(WrappedPeerId),
    /// An incoming gossip request
    NetworkRequest(WrappedPeerId, GossipRequest, ResponseChannel<AuthenticatedGossipResponse>),
    /// An incoming gossip response
    NetworkResponse(WrappedPeerId, GossipResponse),
    /// An incoming pubsub message
    Pubsub(PubsubMessage),
}
