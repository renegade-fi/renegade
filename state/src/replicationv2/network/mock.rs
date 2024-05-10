//! Mock networking implementation for testing

use openraft::error::{InstallSnapshotError, RPCError, RaftError};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{RaftNetwork, RaftNetworkFactory};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

use crate::replicationv2::{Node, NodeId, TypeConfig};

use super::{RaftRequest, RaftResponse};

/// The sender type for the response queue
pub type ResponseSender = OneshotSender<RaftResponse>;
/// The receiver type for the response queue
pub type ResponseReceiver = OneshotReceiver<RaftResponse>;
/// The sender type for the switch queue
pub type SwitchSender = UnboundedSender<(NodeId, RaftRequest, ResponseSender)>;
/// The receiver type for the switch queue
pub type SwitchReceiver = UnboundedReceiver<(NodeId, RaftRequest, ResponseSender)>;
/// Create a new response sender and receiver
fn new_response_queue() -> (ResponseSender, ResponseReceiver) {
    oneshot_channel()
}
/// Create a new switch sender and receiver
pub fn new_switch_queue() -> (SwitchSender, SwitchReceiver) {
    unbounded_channel()
}

/// The mock network node,
#[derive(Clone)]
pub struct MockNetworkNode {
    /// The target this client is sending to
    ///
    /// Set to zero on initialization, the factory trait that `openraft`
    /// requires will set this value appropriately
    target: NodeId,
    /// A sender to the network switch queue
    switch_sender: SwitchSender,
}

impl MockNetworkNode {
    /// Create a new node using the given channel to send to the network switch
    pub fn new(sender: SwitchSender) -> Self {
        Self { target: 0, switch_sender: sender }
    }

    /// Send an RPC to the switch
    pub async fn send_rpc(
        &mut self,
        rpc: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let (send, recv) = new_response_queue();
        self.switch_sender.send((self.target, rpc, send)).expect("channel closed");

        let resp = recv.await.unwrap();
        Ok(resp)
    }
}

impl RaftNetworkFactory<TypeConfig> for MockNetworkNode {
    type Network = Self;

    // Fill in the target and return a clone of `self`
    async fn new_client(&mut self, target: NodeId, _node: &Node) -> Self::Network {
        let mut clone = self.clone();
        clone.target = target;
        clone
    }
}

impl RaftNetwork<TypeConfig> for MockNetworkNode {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let resp = self.send_rpc(RaftRequest::AppendEntries(rpc)).await.unwrap();
        Ok(resp.into_append_entries())
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, Node, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let resp = self.send_rpc(RaftRequest::InstallSnapshot(rpc)).await.unwrap();
        Ok(resp.into_install_snapshot())
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let resp = self.send_rpc(RaftRequest::Vote(rpc)).await.unwrap();
        Ok(resp.into_vote())
    }
}
