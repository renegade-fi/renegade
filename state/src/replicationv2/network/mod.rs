//! Networking implement that shims between the consensus engine and the gossip
//! layer
mod address_translation;

use openraft::{
    error::{InstallSnapshotError, RPCError, RaftError},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    RaftNetwork, RaftNetworkFactory,
};

use super::{Node, NodeId, TypeConfig};

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
