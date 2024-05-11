//! Networking implement that shims between the consensus engine and the gossip
//! layer
mod address_translation;
#[cfg(test)]
pub mod mock;

use openraft::{
    add_async_trait,
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    RaftNetwork, RaftNetworkFactory,
};
use serde::{Deserialize, Serialize};

use crate::StateTransition;

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
    ForwardedProposal(StateTransition),
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

/// A generalization of the raft network trait that specifically allows for
/// point-to-point communication
///
/// We implement the general raft network trait for all types that fit this
/// signature by simply calling out to the p2p implementation
#[add_async_trait]
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
/// `RaftNetwork` implementation
#[derive(Clone)]
pub struct P2PRaftNetworkWrapper<T: P2PRaftNetwork> {
    /// The inner p2p network
    inner: T,
}

impl<T: P2PRaftNetwork> P2PRaftNetworkWrapper<T> {
    /// Create a new wrapper around the p2p network
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Get the inner p2p network
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner p2p network
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: P2PRaftNetwork> RaftNetwork<TypeConfig> for P2PRaftNetworkWrapper<T> {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let target = self.inner().target();
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
        let target = self.inner().target();
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
        let target = self.inner().target();
        let req = RaftRequest::Vote(rpc);
        self.inner.send_request(target, req).await.map(|resp| resp.into_vote())
    }
}

/// The network shim
#[derive(Clone)]
pub struct Network {}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Self;

    async fn new_client(&mut self, _target: NodeId, _node: &Node) -> Self::Network {
        self.clone()
    }
}

impl RaftNetwork<TypeConfig> for Network {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        todo!()
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, Node, RaftError<NodeId, InstallSnapshotError>>,
    > {
        unimplemented!()
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        unimplemented!()
    }
}
