//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use gossip_api::{
    pubsub::PubsubMessage,
    request_response::{AuthenticatedGossipResponse, GossipRequest, GossipResponse},
};
use libp2p::request_response::ResponseChannel;

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
#[derive(Debug)]
pub enum GossipServerJob {
    /// An incoming gossip request
    NetworkRequest(GossipRequest, ResponseChannel<AuthenticatedGossipResponse>),
    /// An incoming gossip response
    NetworkResponse(GossipResponse),
    /// An incoming pubsub message
    Pubsub(PubsubMessage),
}
