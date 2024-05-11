//! Mock networking implementation for testing

use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::RaftNetworkFactory;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

use crate::replicationv2::{Node, NodeId, TypeConfig};

use super::{P2PRaftNetwork, P2PRaftNetworkWrapper, RaftRequest, RaftResponse};

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
}

impl RaftNetworkFactory<TypeConfig> for MockNetworkNode {
    type Network = P2PRaftNetworkWrapper<Self>;

    // Fill in the target and return a clone of `self`
    async fn new_client(&mut self, target: NodeId, _node: &Node) -> Self::Network {
        let mut clone = self.clone();
        clone.target = target;
        P2PRaftNetworkWrapper::new(clone)
    }
}

impl P2PRaftNetwork for MockNetworkNode {
    fn target(&self) -> NodeId {
        self.target
    }

    async fn send_request(
        &self,
        target: NodeId,
        request: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>> {
        let (send, recv) = new_response_queue();
        self.switch_sender.send((target, request, send)).expect("channel closed");

        recv.await.map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }
}
