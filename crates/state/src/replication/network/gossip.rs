//! Gossip networking interface, acts as a shim between raft and our gossip
//! layer

use std::time::Duration;

use async_trait::async_trait;
use gossip_api::request_response::{GossipRequestType, GossipResponse, GossipResponseType};
use job_types::network_manager::{NetworkManagerJob, NetworkManagerQueue};
use openraft::error::{NetworkError, RPCError, RaftError};
use tracing::instrument;

use crate::{
    ciborium_deserialize, ciborium_serialize,
    replication::{
        Node, NodeId,
        error::{ReplicationError, new_network_error},
    },
};

use super::{P2PNetworkFactory, P2PRaftNetwork, P2PRaftNetworkWrapper, RaftRequest, RaftResponse};

/// The error message emitted when a response type is invalid
const ERR_INVALID_RESPONSE: &str = "invalid response type from raft peer";

/// The maximum time to wait for a reply to a raft RPC before failing it as a
/// (recoverable, openraft-retried) network error. An unbounded await here lets a
/// never-answering peer or leader hang the caller -- e.g. a forwarded client
/// write -- indefinitely.
const RAFT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Construct a new `GossipNetwork` instance without target specified
    pub fn empty(network_sender: NetworkManagerQueue) -> Self {
        Self { target: NodeId::default(), target_info: Node::default(), network_sender }
    }

    /// Convert a gossip response into a raft response
    fn to_raft_response(resp: GossipResponse) -> Result<RaftResponse, ReplicationError> {
        let resp_bytes = match resp.body {
            GossipResponseType::Raft(x) => x,
            _ => {
                return Err(ReplicationError::deserialize(ERR_INVALID_RESPONSE));
            },
        };

        let raft_resp = Self::deserialize_raft_response(&resp_bytes)?;
        Ok(raft_resp)
    }

    /// Deserialize a raft response from bytes
    fn deserialize_raft_response(msg_bytes: &[u8]) -> Result<RaftResponse, ReplicationError> {
        ciborium_deserialize(msg_bytes).map_err(ReplicationError::deserialize)
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
        // A failed send/recv here means the network manager queue is closed or
        // the peer/response channel is gone (teardown, peer loss). That's a
        // recoverable *network* error -- openraft will retry -- NOT a reason to
        // panic, which would take down the raft core (and the node's leadership).
        self.network_sender.send(job).map_err(|_| {
            new_network_error(ReplicationError::Raft(
                "failed to send raft RPC: network manager queue closed".to_string(),
            ))
        })?;

        let resp = match tokio::time::timeout(RAFT_RPC_TIMEOUT, rx).await {
            Ok(res) => res.map_err(|_| {
                new_network_error(ReplicationError::Raft(
                    "raft RPC response channel closed before a reply".to_string(),
                ))
            })?,
            Err(_) => {
                return Err(new_network_error(ReplicationError::Raft(
                    "raft RPC response timed out".to_string(),
                )));
            },
        };
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
