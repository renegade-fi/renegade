//! Groups API routes and handlers for network information API operations

// ------------------
// | Error Messages |
// ------------------

// ---------------
// | HTTP Routes |
// ---------------

use std::collections::HashMap;

use async_trait::async_trait;
use itertools::Itertools;

use crate::{
    api_server::{
        error::ApiServerError,
        router::{TypedHandler, UrlParams},
    },
    external_api::{
        http::network::{GetClusterInfoResponse, GetNetworkTopologyResponse},
        types::{Cluster, Peer},
        EmptyRequestResponse,
    },
    state::RelayerState,
};

use super::parse_cluster_id_from_params;

/// Returns the full network topology known to the local node
pub(super) const GET_NETWORK_TOPOLOGY_ROUTE: &str = "/v0/network";
/// Returns the cluster information for the specified cluster
pub(super) const GET_CLUSTER_INFO_ROUTE: &str = "/v0/network/clusters/:cluster_id";

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the GET "/network/clusters" route
#[derive(Clone, Debug)]
pub struct GetNetworkTopologyHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetNetworkTopologyHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetNetworkTopologyHandler {
    type Request = EmptyRequestResponse;
    type Response = GetNetworkTopologyResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Fetch all peer info
        let peers = self
            .global_state
            .read_peer_index()
            .await
            .get_info_map()
            .await;

        // Gather by cluster
        let mut peers_by_cluster: HashMap<String, Vec<Peer>> = HashMap::with_capacity(peers.len());
        for peer in peers.values().cloned() {
            let peer: Peer = peer.into();
            peers_by_cluster
                .entry(peer.cluster_id.clone())
                .or_default()
                .push(peer);
        }

        // Reformat into response
        Ok(GetNetworkTopologyResponse {
            network: peers_by_cluster.into(),
        })
    }
}

/// Handler for the GET "/network/clusters" route
#[derive(Clone, Debug)]
pub struct GetClusterInfoHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetClusterInfoHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetClusterInfoHandler {
    type Request = EmptyRequestResponse;
    type Response = GetClusterInfoResponse;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let cluster_id = parse_cluster_id_from_params(&params)?;

        // For simplicity, fetch all peer info and filter by cluster
        let peers = self
            .global_state
            .read_peer_index()
            .await
            .get_info_map()
            .await;

        let peers: Vec<Peer> = peers
            .into_iter()
            .filter(|(_, peer_info)| peer_info.get_cluster_id().eq(&cluster_id))
            .map(|(_, peer_info)| peer_info.into())
            .collect_vec();

        Ok(GetClusterInfoResponse {
            cluster: Cluster {
                id: cluster_id.to_string(),
                peers,
            },
        })
    }
}
