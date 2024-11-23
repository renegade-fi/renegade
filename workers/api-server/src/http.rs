//! Groups handlers for the HTTP API

mod admin;
mod external_match;
mod network;
mod order_book;
mod price_report;
mod rate_limit;
mod task;
mod wallet;

use admin::{
    AdminGetOrderMatchingPoolHandler, AdminTriggerSnapshotHandler,
    AdminWalletMatchableOrderIdsHandler, IsLeaderHandler,
};
use async_trait::async_trait;
use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    tasks::TaskIdentifier,
    MatchingPoolName,
};
use external_api::{
    http::{
        admin::{
            ADMIN_ASSIGN_ORDER_ROUTE, ADMIN_CREATE_ORDER_IN_MATCHING_POOL_ROUTE,
            ADMIN_GET_ORDER_MATCHING_POOL_ROUTE, ADMIN_MATCHING_POOL_CREATE_ROUTE,
            ADMIN_MATCHING_POOL_DESTROY_ROUTE, ADMIN_OPEN_ORDERS_ROUTE, ADMIN_ORDER_METADATA_ROUTE,
            ADMIN_TRIGGER_SNAPSHOT_ROUTE, ADMIN_WALLET_MATCHABLE_ORDER_IDS_ROUTE, IS_LEADER_ROUTE,
        },
        external_match::{REQUEST_EXTERNAL_MATCH_ROUTE, REQUEST_EXTERNAL_QUOTE_ROUTE},
        network::{GET_CLUSTER_INFO_ROUTE, GET_NETWORK_TOPOLOGY_ROUTE, GET_PEER_INFO_ROUTE},
        order_book::{GET_NETWORK_ORDERS_ROUTE, GET_NETWORK_ORDER_BY_ID_ROUTE},
        price_report::PRICE_REPORT_ROUTE,
        task::{GET_TASK_QUEUE_ROUTE, GET_TASK_STATUS_ROUTE},
        task_history::TASK_HISTORY_ROUTE,
        wallet::{
            BACK_OF_QUEUE_WALLET_ROUTE, CANCEL_ORDER_ROUTE, CREATE_WALLET_ROUTE,
            DEPOSIT_BALANCE_ROUTE, FIND_WALLET_ROUTE, GET_BALANCES_ROUTE,
            GET_BALANCE_BY_MINT_ROUTE, GET_ORDER_BY_ID_ROUTE, GET_WALLET_ROUTE,
            ORDER_HISTORY_ROUTE, PAY_FEES_ROUTE, REDEEM_NOTE_ROUTE, REFRESH_WALLET_ROUTE,
            UPDATE_ORDER_ROUTE, WALLET_ORDERS_ROUTE, WITHDRAW_BALANCE_ROUTE,
        },
        PingResponse,
    },
    EmptyRequestResponse,
};
use external_match::{RequestExternalMatchHandler, RequestExternalQuoteHandler};
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error as HyperError, HeaderMap, Method, Request, Response, Server,
};
use num_bigint::BigUint;
use num_traits::Num;
use rate_limit::WalletTaskRateLimiter;
use state::State;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use util::get_current_time_millis;
use uuid::Uuid;

use crate::{
    error::{bad_request, not_found},
    router::QueryParams,
};

use self::{
    admin::{
        AdminAssignOrderToMatchingPoolHandler, AdminCreateMatchingPoolHandler,
        AdminCreateOrderInMatchingPoolHandler, AdminDestroyMatchingPoolHandler,
        AdminOpenOrdersHandler, AdminOrderMetadataHandler,
    },
    network::{GetClusterInfoHandler, GetNetworkTopologyHandler, GetPeerInfoHandler},
    order_book::{GetNetworkOrderByIdHandler, GetNetworkOrdersHandler},
    price_report::PriceReportHandler,
    task::{GetTaskHistoryHandler, GetTaskQueueHandler, GetTaskStatusHandler},
    wallet::{
        CancelOrderHandler, CreateOrderHandler, CreateWalletHandler, DepositBalanceHandler,
        FindWalletHandler, GetBackOfQueueWalletHandler, GetBalanceByMintHandler,
        GetBalancesHandler, GetOrderByIdHandler, GetOrderHistoryHandler, GetOrdersHandler,
        GetWalletHandler, PayFeesHandler, RedeemNoteHandler, RefreshWalletHandler,
        UpdateOrderHandler, WithdrawBalanceHandler,
    },
};

use super::{
    error::ApiServerError,
    router::{Router, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

/// Health check
pub const PING_ROUTE: &str = "/v0/ping";

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a mint cannot be parsed from URL
const ERR_MINT_PARSE: &str = "could not parse mint";
/// Error message displayed when a given order ID is not parsable
const ERR_ORDER_ID_PARSE: &str = "could not parse order id";
/// Error message displayed when a given wallet ID is not parsable
const ERR_WALLET_ID_PARSE: &str = "could not parse wallet id";
/// Error message displayed when a given cluster ID is not parsable
const ERR_CLUSTER_ID_PARSE: &str = "could not parse cluster id";
/// Error message displayed when a given peer ID is not parsable
const ERR_PEER_ID_PARSE: &str = "could not parse peer id";
/// Error message displayed when parsing a task ID from URL fails
const ERR_TASK_ID_PARSE: &str = "could not parse task id";
/// Error message displayed when parsing a matching pool name from URL fails
const ERR_MATCHING_POOL_PARSE: &str = "could not parse matching pool name";

// ----------------
// | URL Captures |
// ----------------

/// The :mint param in a URL
const MINT_URL_PARAM: &str = "mint";
/// The :wallet_id param in a URL
pub(super) const WALLET_ID_URL_PARAM: &str = "wallet_id";
/// The :order_id param in a URL
const ORDER_ID_URL_PARAM: &str = "order_id";
/// The :cluster_id param in a URL
const CLUSTER_ID_URL_PARAM: &str = "cluster_id";
/// The :peer_id param in a URL
const PEER_ID_URL_PARAM: &str = "peer_id";
/// The :task_id param in a URL
const TASK_ID_URL_PARAM: &str = "task_id";
/// The :matching_pool param in a URL / query string
const MATCHING_POOL_PARAM: &str = "matching_pool";

/// A helper to parse out a mint from a URL param
pub(super) fn parse_mint_from_params(params: &UrlParams) -> Result<BigUint, ApiServerError> {
    // Try to parse as a hex string, then fall back to decimal
    let mint_str = params.get(MINT_URL_PARAM).ok_or_else(|| not_found(ERR_MINT_PARSE))?;
    let stripped_param = mint_str.strip_prefix("0x").unwrap_or(mint_str);
    if let Ok(mint) = BigUint::from_str_radix(stripped_param, 16 /* radix */) {
        return Ok(mint);
    }

    params.get(MINT_URL_PARAM).unwrap().parse().map_err(|_| bad_request(ERR_MINT_PARSE))
}

/// A helper to parse out a wallet ID from a URL param
pub(super) fn parse_wallet_id_from_params(params: &UrlParams) -> Result<Uuid, ApiServerError> {
    params
        .get(WALLET_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_WALLET_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_WALLET_ID_PARSE))
}

/// A helper to parse out an order ID from a URL param
pub(super) fn parse_order_id_from_params(params: &UrlParams) -> Result<Uuid, ApiServerError> {
    params
        .get(ORDER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_ORDER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_ORDER_ID_PARSE))
}

/// A helper to parse out a cluster ID from a URL param
pub(super) fn parse_cluster_id_from_params(
    params: &UrlParams,
) -> Result<ClusterId, ApiServerError> {
    params
        .get(CLUSTER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_CLUSTER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_CLUSTER_ID_PARSE))
}

/// A helper to parse out a peer ID from a URL param
pub(super) fn parse_peer_id_from_params(
    params: &UrlParams,
) -> Result<WrappedPeerId, ApiServerError> {
    params
        .get(PEER_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_PEER_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_PEER_ID_PARSE))
}

/// A helper to parse out a task ID from a URL param
pub(super) fn parse_task_id_from_params(
    params: &UrlParams,
) -> Result<TaskIdentifier, ApiServerError> {
    params
        .get(TASK_ID_URL_PARAM)
        .ok_or_else(|| bad_request(ERR_TASK_ID_PARSE))?
        .parse()
        .map_err(|_| bad_request(ERR_TASK_ID_PARSE))
}

/// A helper to parse out a matching pool name from a URL param
pub(super) fn parse_matching_pool_from_url_params(
    params: &UrlParams,
) -> Result<MatchingPoolName, ApiServerError> {
    params.get(MATCHING_POOL_PARAM).ok_or_else(|| bad_request(ERR_MATCHING_POOL_PARSE)).cloned()
}

/// A helper to parse out a matching pool name from a query string
pub(super) fn parse_matching_pool_from_query_params(
    params: &QueryParams,
) -> Option<MatchingPoolName> {
    params.get(MATCHING_POOL_PARAM).cloned()
}

/// A wrapper around the router and task management operations that
/// the worker may delegate to

#[derive(Clone)]
pub(super) struct HttpServer {
    /// The http router, used to dispatch requests to handlers
    router: Arc<Router>,
    /// The API server config
    config: ApiServerConfig,
}

impl HttpServer {
    /// Create a new http server
    pub(super) fn new(config: ApiServerConfig, state: State) -> Self {
        // Build the router, server, and register routes
        let router = Self::build_router(&config, state);
        Self { router: Arc::new(router), config }
    }

    /// Build a router and register routes on it
    fn build_router(config: &ApiServerConfig, state: State) -> Router {
        // Build the router and register its routes
        let mut router = Router::new(config.admin_api_key, state.clone());
        let wallet_rate_limiter = WalletTaskRateLimiter::new_hourly(config.wallet_task_rate_limit);
        let handshake_queue = config.handshake_manager_work_queue.clone();

        // --- Misc Routes --- //

        // The "/price_report" route
        router.add_unauthenticated_route(
            &Method::POST,
            PRICE_REPORT_ROUTE.to_string(),
            PriceReportHandler::new(config.clone()),
        );

        // The "/ping" route
        router.add_unauthenticated_route(&Method::GET, PING_ROUTE.to_string(), PingHandler::new());

        // --- Wallet Routes --- //

        // The "/task/:id" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_TASK_STATUS_ROUTE.to_string(),
            GetTaskStatusHandler::new(state.clone()),
        );

        // The "/task_queue/:wallet_id" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            GET_TASK_QUEUE_ROUTE.to_string(),
            GetTaskQueueHandler::new(state.clone()),
        );

        // The "/wallet/:wallet_id/task-history" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            TASK_HISTORY_ROUTE.to_string(),
            GetTaskHistoryHandler::new(state.clone()),
        );

        // The "/wallet/:id" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            GET_WALLET_ROUTE.to_string(),
            GetWalletHandler::new(state.clone()),
        );

        // The "/wallet/:id/back_of_queue" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            BACK_OF_QUEUE_WALLET_ROUTE.to_string(),
            GetBackOfQueueWalletHandler::new(state.clone()),
        );

        // The "/wallet" route
        router.add_unauthenticated_route(
            &Method::POST,
            CREATE_WALLET_ROUTE.to_string(),
            CreateWalletHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The "/wallet/lookup" route
        router.add_unauthenticated_route(
            &Method::POST,
            FIND_WALLET_ROUTE.to_string(),
            FindWalletHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The "/wallet/:id/refresh" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            REFRESH_WALLET_ROUTE.to_string(),
            RefreshWalletHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // Getter for the "/wallet/:id/orders" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            WALLET_ORDERS_ROUTE.to_string(),
            GetOrdersHandler::new(state.clone()),
        );

        // Post to the "/wallet/:id/orders" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            WALLET_ORDERS_ROUTE.to_string(),
            CreateOrderHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The "/wallet/:id/orders/:id" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            GET_ORDER_BY_ID_ROUTE.to_string(),
            GetOrderByIdHandler::new(state.clone()),
        );

        // The "/wallet/:id/orders/:id/update" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            UPDATE_ORDER_ROUTE.to_string(),
            UpdateOrderHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The "/wallet/:id/orders/:id/cancel" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            CANCEL_ORDER_ROUTE.to_string(),
            CancelOrderHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The "/wallet/:id/balances" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            GET_BALANCES_ROUTE.to_string(),
            GetBalancesHandler::new(state.clone()),
        );

        // The "/wallet/:id/balances/:mint" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            GET_BALANCE_BY_MINT_ROUTE.to_string(),
            GetBalanceByMintHandler::new(state.clone()),
        );

        // The "/wallet/:id/balances/deposit" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            DEPOSIT_BALANCE_ROUTE.to_string(),
            DepositBalanceHandler::new(
                config.min_transfer_amount,
                config.compliance_service_url.clone(),
                state.clone(),
                wallet_rate_limiter.clone(),
                config.price_reporter_work_queue.clone(),
            ),
        );

        // The "/wallet/:id/balances/:mint/withdraw" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            WITHDRAW_BALANCE_ROUTE.to_string(),
            WithdrawBalanceHandler::new(
                config.min_transfer_amount,
                state.clone(),
                wallet_rate_limiter.clone(),
                config.price_reporter_work_queue.clone(),
            ),
        );

        // The "/wallet/:id/redeem-note" route
        router.add_wallet_authenticated_route(
            &Method::POST,
            REDEEM_NOTE_ROUTE.to_string(),
            RedeemNoteHandler::new(state.clone(), wallet_rate_limiter.clone()),
        );

        // The `wallet/:id/pay-fees` route
        router.add_wallet_authenticated_route(
            &Method::POST,
            PAY_FEES_ROUTE.to_string(),
            PayFeesHandler::new(state.clone()),
        );

        // The "/wallet/:id/order-history" route
        router.add_wallet_authenticated_route(
            &Method::GET,
            ORDER_HISTORY_ROUTE.to_string(),
            GetOrderHistoryHandler::new(state.clone()),
        );

        // --- External Match Routes --- //

        // The "/external-match/quote" route
        router.add_admin_authenticated_route(
            &Method::POST,
            REQUEST_EXTERNAL_QUOTE_ROUTE.to_string(),
            RequestExternalQuoteHandler::new(
                config.min_order_size,
                handshake_queue.clone(),
                config.price_reporter_work_queue.clone(),
                state.clone(),
                config.system_bus.clone(),
            ),
        );

        // The "/external-match/request" route
        router.add_admin_authenticated_route(
            &Method::POST,
            REQUEST_EXTERNAL_MATCH_ROUTE.to_string(),
            RequestExternalMatchHandler::new(
                config.min_order_size,
                handshake_queue,
                config.arbitrum_client.clone(),
                config.system_bus.clone(),
                state.clone(),
                config.price_reporter_work_queue.clone(),
            ),
        );

        // --- Orderbook Routes --- //

        // The "/order_book/orders" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_NETWORK_ORDERS_ROUTE.to_string(),
            GetNetworkOrdersHandler::new(state.clone()),
        );

        // The "/order_book/orders/:id" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_NETWORK_ORDER_BY_ID_ROUTE.to_string(),
            GetNetworkOrderByIdHandler::new(state.clone()),
        );

        // --- Network Routes --- //

        // The "/network" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_NETWORK_TOPOLOGY_ROUTE.to_string(),
            GetNetworkTopologyHandler::new(state.clone()),
        );

        // The "/network/clusters/:id" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_CLUSTER_INFO_ROUTE.to_string(),
            GetClusterInfoHandler::new(state.clone()),
        );

        // The "/network/peers/:id" route
        router.add_unauthenticated_route(
            &Method::GET,
            GET_PEER_INFO_ROUTE.to_string(),
            GetPeerInfoHandler::new(state.clone()),
        );

        // --- Admin Routes --- //

        // The "/admin/is-leader" route
        router.add_unauthenticated_route(
            &Method::GET,
            IS_LEADER_ROUTE.to_string(),
            IsLeaderHandler::new(state.clone()),
        );

        // The "/admin/trigger-snapshot" route
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_TRIGGER_SNAPSHOT_ROUTE.to_string(),
            AdminTriggerSnapshotHandler::new(state.clone()),
        );

        // The "/admin/open-orders" route
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_OPEN_ORDERS_ROUTE.to_string(),
            AdminOpenOrdersHandler::new(state.clone()),
        );

        // The "/admin/orders/:id/metadata" route
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_ORDER_METADATA_ROUTE.to_string(),
            AdminOrderMetadataHandler::new(state.clone(), config.price_reporter_work_queue.clone()),
        );

        // The "/admin/wallet/:id/matchable-order-ids" route
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_WALLET_MATCHABLE_ORDER_IDS_ROUTE.to_string(),
            AdminWalletMatchableOrderIdsHandler::new(state.clone()),
        );

        // The "/admin/matching_pools/:matching_pool" route
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_MATCHING_POOL_CREATE_ROUTE.to_string(),
            AdminCreateMatchingPoolHandler::new(state.clone()),
        );

        // The "/admin/matching_pools/:matching_pool/destroy" route
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_MATCHING_POOL_DESTROY_ROUTE.to_string(),
            AdminDestroyMatchingPoolHandler::new(state.clone()),
        );

        // The "/admin/wallet/:id/order-in-pool" route
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_CREATE_ORDER_IN_MATCHING_POOL_ROUTE.to_string(),
            AdminCreateOrderInMatchingPoolHandler::new(state.clone()),
        );

        // The "/admin/orders/:id/assign-pool/:matching_pool" route
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_ASSIGN_ORDER_ROUTE.to_string(),
            AdminAssignOrderToMatchingPoolHandler::new(
                state.clone(),
                config.handshake_manager_work_queue.clone(),
            ),
        );

        // The "/admin/orders/:id/matching-pool" route
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_GET_ORDER_MATCHING_POOL_ROUTE.to_string(),
            AdminGetOrderMatchingPoolHandler::new(state),
        );

        router
    }

    /// The execution loop for the http server, accepts incoming connections,
    /// serves them, and awaits the next connection
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        // Build an HTTP handler callback
        // Clone self and move it into each layer of the callback so that each
        // scope has its own copy of self
        let self_clone = self.clone();
        let make_service = make_service_fn(move |_: &AddrStream| {
            let self_clone = self_clone.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let self_clone = self_clone.clone();
                    async move { Ok::<_, HyperError>(self_clone.serve_request(req).await) }
                }))
            }
        });

        // Build the http server and enter its execution loop
        let addr: SocketAddr = format!("0.0.0.0:{}", self.config.http_port).parse().unwrap();
        Server::bind(&addr)
            .serve(make_service)
            .await
            .map_err(|err| ApiServerError::HttpServerFailure(err.to_string()))
    }

    /// Serve an http request
    async fn serve_request(&self, req: Request<Body>) -> Response<Body> {
        self.router.handle_req(req.method().to_owned(), req.uri().clone(), req).await
    }
}

/// Handler for the ping route, returns a pong
#[derive(Clone, Debug, Default)]
pub struct PingHandler;
impl PingHandler {
    /// Create a new handler for "/ping"
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl TypedHandler for PingHandler {
    type Request = EmptyRequestResponse;
    type Response = PingResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let timestamp = get_current_time_millis();
        Ok(PingResponse { timestamp })
    }
}
