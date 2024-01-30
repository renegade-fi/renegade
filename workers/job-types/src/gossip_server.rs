//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use common::types::gossip::WrappedPeerId;
use gossip_api::{
    pubsub::PubsubMessage,
    request_response::{AuthenticatedGossipResponse, GossipRequest, GossipResponse},
};
use libp2p::request_response::ResponseChannel;

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
