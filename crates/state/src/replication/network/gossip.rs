//! Gossip networking interface, acts as a shim between raft and our gossip
//! layer

use async_trait::async_trait;
use gossip_api::request_response::{GossipRequestType, GossipResponse, GossipResponseType};
use job_types::network_manager::{NetworkManagerJob, NetworkManagerQueue};
use openraft::error::{NetworkError, RPCError, RaftError};
use tracing::instrument;
use util::err_str;

use crate::{
    ciborium_serialize,
    replication::{
        Node, NodeId,
        error::{ReplicationError, new_network_error},
    },
};

use super::{P2PNetworkFactory, P2PRaftNetwork, P2PRaftNetworkWrapper, RaftRequest, RaftResponse};

/// The error message emitted when a response type is invalid
const ERR_INVALID_RESPONSE: &str = "invalid response type from raft peer";

/// The network shim
#[derive(Clone)]
pub struct GossipNetwork {
    /// The target node for this instance
    target: NodeId,
    /// The target node info
    target_info: Node,
    /// A sender to the network manager's queue
    network_sender: NetworkManagerQueue,
}

impl GossipNetwork {
    /// Constructor
    pub fn new(target: NodeId, target_info: Node, network_sender: NetworkManagerQueue) -> Self {
        Self { target, target_info, network_sender }
    }

    /// Construct a new `GossipNetwork` instance without target specified
    pub fn empty(network_sender: NetworkManagerQueue) -> Self {
        Self { target: NodeId::default(), target_info: Node::default(), network_sender }
    }

    /// Convert a gossip response into a raft response
    fn to_raft_response(resp: GossipResponse) -> Result<RaftResponse, ReplicationError> {
        let resp_bytes = match resp.body {
            GossipResponseType::Raft(x) => x,
            _ => {
                return Err(ReplicationError::Deserialize(ERR_INVALID_RESPONSE.to_string()));
            },
        };

        let raft_resp = Self::deserialize_raft_response(&resp_bytes)?;
        Ok(raft_resp)
    }

    /// Deserialize a raft response from bytes
    fn deserialize_raft_response(msg_bytes: &[u8]) -> Result<RaftResponse, ReplicationError> {
        ciborium::de::from_reader(msg_bytes).map_err(err_str!(ReplicationError::Deserialize))
    }
}

#[async_trait]
impl P2PRaftNetwork for GossipNetwork {
    fn target(&self) -> NodeId {
        self.target
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        name = "send_raft_request", 
        skip_all, err
        fields(req_type = %request.type_str())
    )]
    async fn send_request(
        &self,
        _target: NodeId,
        request: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>> {
        // We serialize in the raft layer to avoid the `gossip-api` depending on `state`
        let ser =
            ciborium_serialize(&request).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let req = GossipRequestType::Raft(ser);

        // Send a network manager job
        let peer_id = self.target_info.peer_id;
        let (job, rx) = NetworkManagerJob::request_with_response(peer_id, req);
        self.network_sender.send(job).unwrap();

        // TODO: timeout and error handling
        let resp = rx.await.unwrap();
        Self::to_raft_response(resp).map_err(new_network_error)
    }
}

impl P2PNetworkFactory for GossipNetwork {
    fn new_p2p_client(&self, target: NodeId, target_info: Node) -> P2PRaftNetworkWrapper {
        let mut clone = self.clone();
        clone.target = target;
        clone.target_info = target_info;

        P2PRaftNetworkWrapper::new(clone)
    }
}
