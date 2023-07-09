//! Groups API routes and handlers for network information API operations

use std::collections::HashMap;

use async_trait::async_trait;
use external_api::{
    http::network::{GetClusterInfoResponse, GetNetworkTopologyResponse, GetPeerInfoResponse},
    types::{Cluster, Peer},
    EmptyRequestResponse,
};
use hyper::{HeaderMap, StatusCode};
use itertools::Itertools;
use state::RelayerState;

use crate::{
    error::ApiServerError,
    router::{TypedHandler, UrlParams},
};

use super::{parse_cluster_id_from_params, parse_peer_id_from_params};

// ------------------
// | Error Messages |
// ------------------

/// Error displayed when a requested peer could not be found in the peer index
const ERR_PEER_NOT_FOUND: &str = "could not find peer in index";

// ---------------
// | HTTP Routes |
// ---------------

/// Returns the full network topology known to the local node
pub(super) const GET_NETWORK_TOPOLOGY_ROUTE: &str = "/v0/network";
/// Returns the cluster information for the specified cluster
pub(super) const GET_CLUSTER_INFO_ROUTE: &str = "/v0/network/clusters/:cluster_id";
/// Returns the peer info for a given peer
pub(super) const GET_PEER_INFO_ROUTE: &str = "/v0/network/peers/:peer_id";

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
        _headers: HeaderMap,
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
        _headers: HeaderMap,
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

/// Handler for the GET "/network/clusters" route
#[derive(Clone, Debug)]
pub struct GetPeerInfoHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetPeerInfoHandler {
    /// Constructor
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetPeerInfoHandler {
    type Request = EmptyRequestResponse;
    type Response = GetPeerInfoResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let peer_id = parse_peer_id_from_params(&params)?;
        if let Some(info) = self
            .global_state
            .read_peer_index()
            .await
            .get_peer_info(&peer_id)
            .await
        {
            Ok(GetPeerInfoResponse { peer: info.into() })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_PEER_NOT_FOUND.to_string(),
            ))
        }
    }
}
