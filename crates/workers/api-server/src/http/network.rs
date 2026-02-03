//! Groups API routes and handlers for network information API operations

use std::collections::HashMap;

use async_trait::async_trait;
use external_api::{EmptyRequestResponse, http::network::GetNetworkTopologyResponse, types::Peer};
use hyper::HeaderMap;
use state::State;
use types_core::Chain;
use types_gossip::PeerInfo;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

// -----------
// | Helpers |
// -----------

/// Convert a PeerInfo to a Peer API type
fn peer_info_to_peer(peer_info: PeerInfo) -> Peer {
    Peer {
        id: peer_info.get_peer_id().to_string(),
        cluster_id: peer_info.get_cluster_id().to_string(),
        addr: peer_info.get_addr().to_string(),
        is_leader: false,
    }
}

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the GET "/v2/network" route
#[derive(Clone)]
pub struct GetNetworkTopologyHandler {
    /// The chain to report topology on
    chain: Chain,
    /// A copy of the relayer-global state
    state: State,
}

impl GetNetworkTopologyHandler {
    /// Constructor
    pub fn new(chain: Chain, state: State) -> Self {
        Self { chain, state }
    }
}

#[async_trait]
impl TypedHandler for GetNetworkTopologyHandler {
    type Request = EmptyRequestResponse;
    type Response = GetNetworkTopologyResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Fetch all peer info
        let local_cluster_id = self.state.get_cluster_id()?.to_string();
        let peers = self.state.get_peer_info_map().await?;

        // Gather by cluster
        let mut peers_by_cluster: HashMap<String, Vec<Peer>> = HashMap::with_capacity(peers.len());
        for peer in peers.values().cloned() {
            let peer: Peer = peer_info_to_peer(peer);
            peers_by_cluster.entry(peer.cluster_id.clone()).or_default().push(peer);
        }

        // Mark the local cluster's leader as such
        if let Some(leader_id) = self.state.get_leader()
            && let Some(peers) = peers_by_cluster.get_mut(&local_cluster_id)
        {
            let leader_str = leader_id.to_string();
            peers.iter_mut().for_each(|peer| {
                if peer.id == leader_str {
                    peer.is_leader = true;
                }
            });
        }

        // Reformat into response
        let network =
            external_api::types::Network::from_cluster_peer_map(self.chain, peers_by_cluster);
        Ok(GetNetworkTopologyResponse { local_cluster_id, network })
    }
}
