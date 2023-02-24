//! Groups job definitions for the gossip server
//! These jobs are enqueued for execution by other workers within the relayer

use libp2p::request_response::ResponseChannel;

use crate::{
    api::{
        cluster_management::{ClusterJoinMessage, ReplicateRequestBody, ValidityProofRequest},
        gossip::AuthenticatedGossipResponse,
        heartbeat::{BootstrapRequest, HeartbeatMessage},
    },
    proof_generation::jobs::ValidCommitmentsBundle,
    state::{wallet::WalletIdentifier, NetworkOrder, OrderIdentifier},
    types::SizedValidCommitmentsWitness,
};

use super::types::{ClusterId, WrappedPeerId};

/// Defines a heartbeat job that can be enqueued by other workers in a relayer
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GossipServerJob {
    /// Handle a job to bootstrap a newly added peer
    Bootstrap(
        BootstrapRequest,
        ResponseChannel<AuthenticatedGossipResponse>,
    ),
    /// Handle an incoming cluster management job
    Cluster(ClusterManagementJob),
    /// Job type for the heartbeat executor to send an outbound heartbeat request
    ExecuteHeartbeat(WrappedPeerId),
    /// Handle an incoming heartbeat request from a peer
    HandleHeartbeatReq {
        /// The peer sending the request
        peer_id: WrappedPeerId,
        /// The message contents
        message: HeartbeatMessage,
        /// A channel on which to send the response
        channel: ResponseChannel<AuthenticatedGossipResponse>,
    },
    /// Handle an incoming heartbeat response from a peer
    HandleHeartbeatResp {
        /// The peer sending a heartbeat response
        peer_id: WrappedPeerId,
        /// The message contents
        message: HeartbeatMessage,
    },
    /// Handle an orderbook management message from a gossip peer
    OrderBookManagement(OrderBookManagementJob),
}

/// Defines a job type for a cluster management tasks
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ClusterManagementJob {
    /// Add a replica for a given wallet to the state and begin gossip operations
    /// for that wallet
    AddWalletReplica {
        /// The ID fo the wallet that is newly replicated
        wallet_id: WalletIdentifier,
        /// The ID of the peer that has just replicated the wallet
        peer_id: WrappedPeerId,
    },
    /// A request from a peer to join the local peer's cluster
    ClusterJoinRequest(ClusterId, ClusterJoinMessage),
    /// Replicate a set of wallets forwarded from a peer
    ReplicateRequest(ReplicateRequestBody),
    /// Forward any known proofs of order validity to the sending cluster peer
    ShareValidityProofs(ValidityProofRequest),
    /// A proof has been shared by a cluster peer
    UpdateValidityProof(OrderIdentifier, ValidCommitmentsBundle),
}

/// Defines a job type for local order book management
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::enum_variant_names)]
pub enum OrderBookManagementJob {
    /// A request for order information has come in
    OrderInfo {
        /// The order ID that info is requested for
        order_id: OrderIdentifier,
        /// The channel to response to the request on
        response_channel: ResponseChannel<AuthenticatedGossipResponse>,
    },
    /// A response from a request for order information has come in
    OrderInfoResponse {
        /// The order ID that info was requested for
        order_id: OrderIdentifier,
        /// The info attached to the order
        info: Option<NetworkOrder>,
    },
    /// A new order has been added to the book, peers should place it in the
    /// received state in their local book
    OrderReceived {
        /// The identifier of the new order
        order_id: OrderIdentifier,
        /// The cluster that manages this order
        cluster: ClusterId,
    },
    /// A new validity proof has been generated for an order, it should be placed in
    /// the `Verified` state after local peers verify the proof
    OrderProofUpdated {
        /// The identifier of the now updated order
        order_id: OrderIdentifier,
        /// The cluster that manages this order
        cluster: ClusterId,
        /// The new proof of `VALID COMMITMENTS`
        proof: ValidCommitmentsBundle,
    },
    /// A request for an order's witness to `VALID COMMITMENTS` has come in
    OrderWitness {
        /// The order ID that info is requested for
        order_id: OrderIdentifier,
        /// The peer to return the response to
        requesting_peer: WrappedPeerId,
    },
    /// A response for an order's witness to `VALID COMMITMENTS` has come in
    OrderWitnessResponse {
        /// The order ID that info is requested for
        order_id: OrderIdentifier,
        /// The witness used to prove `VALID COMMITMENTS` for the order
        witness: SizedValidCommitmentsWitness,
    },
}
