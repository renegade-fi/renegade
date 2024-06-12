//! Groups API routes and handlers for network information API operations

use std::collections::HashMap;

use async_trait::async_trait;
use external_api::{
    http::network::{GetClusterInfoResponse, GetNetworkTopologyResponse, GetPeerInfoResponse},
    types::{Cluster, Peer},
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use itertools::Itertools;
use state::State;

use crate::{
    error::{not_found, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::{parse_cluster_id_from_params, parse_peer_id_from_params};

// ------------------
// | Error Messages |
// ------------------

/// Error displayed when a requested peer could not be found in the peer index
const ERR_PEER_NOT_FOUND: &str = "could not find peer in index";

// ------------------
// | Route Handlers |
// ------------------

/// Handler for the GET "/network/clusters" route
#[derive(Clone)]
pub struct GetNetworkTopologyHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetNetworkTopologyHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        let peers = self.state.get_peer_info_map().await?;

        // Gather by cluster
        let mut peers_by_cluster: HashMap<String, Vec<Peer>> = HashMap::with_capacity(peers.len());
        for peer in peers.values().cloned() {
            let peer: Peer = peer.into();
            peers_by_cluster.entry(peer.cluster_id.clone()).or_default().push(peer);
        }

        // Reformat into response
        Ok(GetNetworkTopologyResponse { network: peers_by_cluster.into() })
    }
}

/// Handler for the GET "/network/clusters" route
#[derive(Clone)]
pub struct GetClusterInfoHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetClusterInfoHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let cluster_id = parse_cluster_id_from_params(&params)?;

        // For simplicity, fetch all peer info and filter by cluster
        let peers = self.state.get_peer_info_map().await?;
        let peers: Vec<Peer> = peers
            .into_iter()
            .filter(|(_, peer_info)| peer_info.get_cluster_id().eq(&cluster_id))
            .map(|(_, peer_info)| peer_info.into())
            .collect_vec();

        Ok(GetClusterInfoResponse { cluster: Cluster { id: cluster_id.to_string(), peers } })
    }
}

/// Handler for the GET "/network/clusters" route
#[derive(Clone)]
pub struct GetPeerInfoHandler {
    /// A copy of the relayer-global state
    state: State,
}

impl GetPeerInfoHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let peer_id = parse_peer_id_from_params(&params)?;
        if let Some(info) = self.state.get_peer_info(&peer_id).await? {
            Ok(GetPeerInfoResponse { peer: info.into() })
        } else {
            Err(not_found(ERR_PEER_NOT_FOUND.to_string()))
        }
    }
}
