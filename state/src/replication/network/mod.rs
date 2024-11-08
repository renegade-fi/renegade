//! Networking implement that shims between the consensus engine and the gossip
//! layer
pub mod gossip;
#[cfg(any(test, feature = "mocks"))]
pub mod mock;

use std::sync::Arc;

use async_trait::async_trait;
use openraft::{
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    RaftNetwork, RaftNetworkFactory,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use util::{err_str, telemetry::helpers::backfill_trace_field};

use crate::{ciborium_serialize, error::StateError, Proposal};

use super::{Node, NodeId, TypeConfig};

// ---------
// | Types |
// ---------

/// The request type a raft node may send to another
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RaftRequest {
    /// A request to append entries
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    /// A request to install a snapshot
    InstallSnapshot(InstallSnapshotRequest<TypeConfig>),
    /// A request to vote
    Vote(VoteRequest<NodeId>),
    /// A proposal forwarded to the leader
    ForwardedProposal(Proposal),
}

impl RaftRequest {
    /// Get a string representing the request type
    pub fn type_str(&self) -> String {
        match self {
            RaftRequest::AppendEntries(req) => {
                format!("append_entries (len = {})", req.entries.len())
            },
            RaftRequest::InstallSnapshot(_) => "install_snapshot".to_string(),
            RaftRequest::Vote(_) => "vote".to_string(),
            RaftRequest::ForwardedProposal(_) => "forwarded_proposal".to_string(),
        }
    }
}

/// The response type a raft node may send to another
#[derive(Debug, Serialize, Deserialize)]
pub enum RaftResponse {
    /// A simple ack when no data must be returned
    Ack,
    /// A response to an append entries request
    AppendEntries(AppendEntriesResponse<NodeId>),
    /// A response to an install snapshot request
    InstallSnapshot(Result<InstallSnapshotResponse<NodeId>, InstallSnapshotError>),
    /// A response to a vote request
    Vote(VoteResponse<NodeId>),
}

impl RaftResponse {
    /// Serialize a raft response to bytes
    #[instrument(name = "RaftResponse::to_bytes", skip_all, fields(size), err)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, StateError> {
        let buf = ciborium_serialize(self).map_err(err_str!(StateError::Serde))?;
        backfill_trace_field("size", buf.len());
        Ok(buf)
    }

    /// Convert the response to an append entries request
    pub fn into_append_entries(self) -> AppendEntriesResponse<NodeId> {
        match self {
            RaftResponse::AppendEntries(resp) => resp,
            _ => panic!("Expected AppendEntries response, got {:?}", self),
        }
    }

    /// Convert the response to an install snapshot request
    pub fn into_install_snapshot(
        self,
    ) -> Result<InstallSnapshotResponse<NodeId>, InstallSnapshotError> {
        match self {
            RaftResponse::InstallSnapshot(resp) => resp,
            _ => panic!("Expected InstallSnapshot response, got {:?}", self),
        }
    }

    /// Convert the response to a vote request
    pub fn into_vote(self) -> VoteResponse<NodeId> {
        match self {
            RaftResponse::Vote(resp) => resp,
            _ => panic!("Expected Vote response, got {:?}", self),
        }
    }
}

// -----------------------------
// | Networking Implementation |
// -----------------------------

/// In the following code, we wrap each of the `openraft` networking traits in
/// our own traits and containers for two reasons:
/// 1. Using our own traits allows us to define default implementations on our
///    containers, meaning that our networking impls must only implement a
///    thinner trait, e.g. `P2PRaftNetwork`.
/// 2. Using our own containers lets us dynamically dispatch networking calls.
///    This prevents a network impl generic from coloring our trait interfaces
///    and containing interfaces. In this end this lets the `State` object be
///    defined non-generically, which is desired

// --- Networking --- //

/// A generalization of the raft network trait that specifically allows for
/// point-to-point communication
///
/// We implement the general raft network trait for all types that fit this
/// signature by simply calling out to the p2p implementation
#[async_trait]
pub trait P2PRaftNetwork: 'static + Sync + Send {
    /// The target this client is sending requests to
    fn target(&self) -> NodeId;
    /// Send an request to the target node
    async fn send_request(
        &self,
        target: NodeId,
        request: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>>;
}

/// A wrapper around the p2p raft network that allows for a default
/// `RaftNetwork` implementation and to hide generics from higher level
/// interfaces
pub struct P2PRaftNetworkWrapper {
    /// The inner p2p network
    inner: Box<dyn P2PRaftNetwork + Send + Sync>,
}

impl P2PRaftNetworkWrapper {
    /// Constructor
    pub fn new<N: P2PRaftNetwork>(inner: N) -> Self {
        Self { inner: Box::new(inner) }
    }
}

#[async_trait]
impl P2PRaftNetwork for P2PRaftNetworkWrapper {
    fn target(&self) -> NodeId {
        self.inner.target()
    }

    async fn send_request(
        &self,
        target: NodeId,
        request: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>> {
        self.inner.send_request(target, request).await
    }
}

impl RaftNetwork<TypeConfig> for P2PRaftNetworkWrapper {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let target = self.inner.target();
        let req = RaftRequest::AppendEntries(rpc);
        self.inner.send_request(target, req).await.map(|resp| resp.into_append_entries())
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, Node, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let target = self.inner.target();
        let req = RaftRequest::InstallSnapshot(rpc);
        let res =
            self.inner.send_request(target, req).await.map(|resp| resp.into_install_snapshot());

        // Map the error to have the correct remote error type
        // We do this because the remote error type can only be reported by the remote
        // peer. Other error types are determined locally by the RPC handler
        if res.is_err() {
            let mapped_err = match res.err().unwrap() {
                RPCError::Network(e) => RPCError::Network(e),
                RPCError::PayloadTooLarge(e) => RPCError::PayloadTooLarge(e),
                RPCError::Timeout(e) => RPCError::Timeout(e),
                RPCError::Unreachable(e) => RPCError::Unreachable(e),
                _ => unreachable!("remote errors sent in response"),
            };

            return Err(mapped_err);
        };

        match res.unwrap() {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let err = RaftError::APIError(e);
                Err(RPCError::RemoteError(RemoteError::new(target, err)))
            },
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let target = self.inner.target();
        let req = RaftRequest::Vote(rpc);
        self.inner.send_request(target, req).await.map(|resp| resp.into_vote())
    }
}

// --- Factory --- //

/// A wrapper trait for the `openraft` network factory
///
/// We define this trait to allow for p2p specific implementation as well as to
/// enable use as a trait object
pub trait P2PNetworkFactory: Send + Sync + 'static {
    /// Create a new p2p client
    fn new_p2p_client(&self, target: NodeId, target_info: Node) -> P2PRaftNetworkWrapper;
}

/// A wrapper type allowing for default implementations of the network factory
/// traits, particularly the foreign `RaftNetworkFactory` trait
#[derive(Clone)]
pub struct P2PNetworkFactoryWrapper {
    /// The inner factory implementation
    inner: Arc<dyn P2PNetworkFactory>,
}

impl P2PNetworkFactoryWrapper {
    /// Constructor
    pub fn new<F: P2PNetworkFactory>(factory: F) -> Self {
        Self { inner: Arc::new(factory) }
    }
}

impl P2PNetworkFactory for P2PNetworkFactoryWrapper {
    fn new_p2p_client(&self, target: NodeId, target_info: Node) -> P2PRaftNetworkWrapper {
        self.inner.new_p2p_client(target, target_info)
    }
}

impl RaftNetworkFactory<TypeConfig> for P2PNetworkFactoryWrapper {
    type Network = P2PRaftNetworkWrapper;

    async fn new_client(&mut self, target: NodeId, target_info: &Node) -> Self::Network {
        self.inner.new_p2p_client(target, *target_info)
    }
}
