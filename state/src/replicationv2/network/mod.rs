//! Networking implement that shims between the consensus engine and the gossip
//! layer
mod address_translation;
#[cfg(test)]
pub mod mock;

use openraft::{
    error::{InstallSnapshotError, RPCError, RaftError},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    RaftNetwork, RaftNetworkFactory,
};
use serde::{Deserialize, Serialize};

use super::{Node, NodeId, TypeConfig};

/// The request type a raft node may send to another
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RaftRequest {
    /// A request to append entries
    AppendEntries(AppendEntriesRequest<TypeConfig>),
    /// A request to install a snapshot
    InstallSnapshot(InstallSnapshotRequest<TypeConfig>),
    /// A request to vote
    Vote(VoteRequest<NodeId>),
}

/// The response type a raft node may send to another
#[derive(Debug, Serialize, Deserialize)]
pub enum RaftResponse {
    /// A response to an append entries request
    AppendEntries(AppendEntriesResponse<NodeId>),
    /// A response to an install snapshot request
    InstallSnapshot(InstallSnapshotResponse<NodeId>),
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
    pub fn into_install_snapshot(self) -> InstallSnapshotResponse<NodeId> {
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
