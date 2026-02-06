//! Groups handlers for the HTTP API

mod account;
mod admin;
mod balance;
mod external_match;
mod helpers;
mod market;
mod metadata;
mod network;
mod order;
mod rate_limit;
mod task;

use account::{
    CreateAccountHandler, GetAccountByIdHandler, GetAccountSeedsHandler, SyncAccountHandler,
};
use admin::{
    AdminCreateMatchingPoolHandler, AdminCreateOrderInPoolHandler, AdminDestroyMatchingPoolHandler,
    AdminGetAccountOrdersHandler, AdminGetOrderByIdHandler, AdminGetOrdersHandler,
    AdminGetTaskQueuePausedHandler, AdminRefreshMatchFeesHandler, AdminRefreshTokenMappingHandler,
    AdminTriggerSnapshotHandler, IsLeaderHandler,
};
use async_trait::async_trait;
use balance::{
    DepositBalanceHandler, GetBalanceByMintHandler, GetBalancesHandler, WithdrawBalanceHandler,
};
use external_api::{
    EmptyRequestResponse,
    http::{
        PingResponse,
        account::{
            CREATE_ACCOUNT_ROUTE, GET_ACCOUNT_BY_ID_ROUTE, GET_ACCOUNT_SEEDS_ROUTE,
            SYNC_ACCOUNT_ROUTE,
        },
        admin::{
            ADMIN_CREATE_ORDER_IN_POOL_ROUTE, ADMIN_GET_ACCOUNT_ORDERS_ROUTE,
            ADMIN_GET_ORDER_BY_ID_ROUTE, ADMIN_GET_ORDERS_ROUTE, ADMIN_GET_TASK_QUEUE_PAUSED_ROUTE,
            ADMIN_MATCHING_POOL_CREATE_ROUTE, ADMIN_MATCHING_POOL_DESTROY_ROUTE,
            ADMIN_REFRESH_MATCH_FEES_ROUTE, ADMIN_REFRESH_TOKEN_MAPPING_ROUTE,
            ADMIN_TRIGGER_SNAPSHOT_ROUTE, IS_LEADER_ROUTE,
        },
        balance::{
            DEPOSIT_BALANCE_ROUTE, GET_BALANCE_BY_MINT_ROUTE, GET_BALANCES_ROUTE,
            WITHDRAW_BALANCE_ROUTE,
        },
        external_match::{ASSEMBLE_MATCH_BUNDLE_ROUTE, GET_EXTERNAL_MATCH_QUOTE_ROUTE},
        market::{
            GET_MARKET_DEPTH_BY_MINT_ROUTE, GET_MARKET_PRICE_ROUTE, GET_MARKETS_DEPTH_ROUTE,
            GET_MARKETS_ROUTE,
        },
        metadata::GET_EXCHANGE_METADATA_ROUTE,
        network::GET_NETWORK_TOPOLOGY_ROUTE,
        order::{
            CANCEL_ORDER_ROUTE, CREATE_ORDER_ROUTE, GET_ORDER_BY_ID_ROUTE, GET_ORDERS_ROUTE,
            UPDATE_ORDER_ROUTE,
        },
        task::{GET_TASK_BY_ID_ROUTE, GET_TASKS_ROUTE},
    },
};
use external_match::handlers::{AssembleMatchBundleHandler, GetExternalMatchQuoteHandler};
use hyper::{
    Error as HyperError, HeaderMap, Method, Request, body::Incoming as IncomingBody,
    server::conn::http1::Builder as Http1Builder, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use market::{
    GetMarketDepthByMintHandler, GetMarketDepthsHandler, GetMarketPriceHandler, GetMarketsHandler,
};
use metadata::GetExchangeMetadataHandler;
use network::GetNetworkTopologyHandler;
use order::{
    CancelOrderHandler, CreateOrderHandler, GetOrderByIdHandler, GetOrdersHandler,
    UpdateOrderHandler,
};
use std::{net::SocketAddr, sync::Arc};
use task::{GetTaskByIdHandler, GetTasksHandler};
use tokio::net::{TcpListener, TcpStream};
use types_core::HmacKey;
use util::get_current_time_millis;

use crate::{http::external_match::processor::ExternalMatchProcessor, router::QueryParams};

use super::{
    error::ApiServerError,
    router::{Router, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

/// Health check
pub const PING_ROUTE: &str = "/v2/ping";

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
    pub(super) fn new(config: ApiServerConfig) -> Result<Self, ApiServerError> {
        // Build the router, server, and register routes
        let router = Self::build_router(&config)?;
        Ok(Self { router: Arc::new(router), config })
    }

    /// Build a router and register routes on it
    fn build_router(config: &ApiServerConfig) -> Result<Router, ApiServerError> {
        // Build the router and register its routes
        let mut router = Router::new(config.admin_api_key, config.state.clone());
        let state = &config.state;
        let darkpool_client = &config.darkpool_client;
        let bus = &config.system_bus;
        let matching_engine_worker_queue = &config.matching_engine_worker_queue;
        let task_queue = &config.task_queue;

        // --- Misc Routes --- //

        // The "/ping" route
        router.add_unauthenticated_route(&Method::GET, PING_ROUTE.to_string(), PingHandler::new());

        // --- Account Routes (v2) --- //

        // POST /v2/account
        router.add_unauthenticated_route(
            &Method::POST,
            CREATE_ACCOUNT_ROUTE.to_string(),
            CreateAccountHandler::new(state.clone(), task_queue.clone()),
        );

        // GET /v2/account/:account_id
        router.add_account_authenticated_route(
            &Method::GET,
            GET_ACCOUNT_BY_ID_ROUTE.to_string(),
            GetAccountByIdHandler::new(state.clone()),
        );

        // GET /v2/account/:account_id/seeds
        router.add_account_authenticated_route(
            &Method::GET,
            GET_ACCOUNT_SEEDS_ROUTE.to_string(),
            GetAccountSeedsHandler::new(state.clone()),
        );

        // POST /v2/account/:account_id/sync
        router.add_account_authenticated_route(
            &Method::POST,
            SYNC_ACCOUNT_ROUTE.to_string(),
            SyncAccountHandler::new(state.clone(), task_queue.clone()),
        );

        // --- Order Routes (v2) --- //

        // GET /v2/account/:account_id/orders
        router.add_account_authenticated_route(
            &Method::GET,
            GET_ORDERS_ROUTE.to_string(),
            GetOrdersHandler::new(state.clone()),
        );

        // POST /v2/account/:account_id/orders
        let executor = state.get_executor_key().map_err(ApiServerError::setup)?.address();
        router.add_account_authenticated_route(
            &Method::POST,
            CREATE_ORDER_ROUTE.to_string(),
            CreateOrderHandler::new(executor, state.clone(), task_queue.clone()),
        );

        // GET /v2/account/:account_id/orders/:order_id
        router.add_account_authenticated_route(
            &Method::GET,
            GET_ORDER_BY_ID_ROUTE.to_string(),
            GetOrderByIdHandler::new(state.clone()),
        );

        // POST /v2/account/:account_id/orders/:order_id/update
        router.add_unauthenticated_route(
            &Method::POST,
            UPDATE_ORDER_ROUTE.to_string(),
            UpdateOrderHandler::new(),
        );

        // POST /v2/account/:account_id/orders/:order_id/cancel
        router.add_account_authenticated_route(
            &Method::POST,
            CANCEL_ORDER_ROUTE.to_string(),
            CancelOrderHandler::new(state.clone(), task_queue.clone()),
        );

        // --- Balance Routes (v2) --- //

        // GET /v2/account/:account_id/balances
        router.add_account_authenticated_route(
            &Method::GET,
            GET_BALANCES_ROUTE.to_string(),
            GetBalancesHandler::new(state.clone()),
        );

        // GET /v2/account/:account_id/balances/:mint
        router.add_account_authenticated_route(
            &Method::GET,
            GET_BALANCE_BY_MINT_ROUTE.to_string(),
            GetBalanceByMintHandler::new(state.clone()),
        );

        // POST /v2/account/:account_id/balances/:mint/deposit
        router.add_account_authenticated_route(
            &Method::POST,
            DEPOSIT_BALANCE_ROUTE.to_string(),
            DepositBalanceHandler::new(state.clone(), task_queue.clone()),
        );

        // POST /v2/account/:account_id/balances/:mint/withdraw
        router.add_account_authenticated_route(
            &Method::POST,
            WITHDRAW_BALANCE_ROUTE.to_string(),
            WithdrawBalanceHandler::new(state.clone(), task_queue.clone()),
        );

        // --- Task Routes (v2) --- //

        // GET /v2/account/:account_id/tasks
        router.add_unauthenticated_route(
            &Method::GET,
            GET_TASKS_ROUTE.to_string(),
            GetTasksHandler::new(),
        );

        // GET /v2/account/:account_id/tasks/:task_id
        router.add_unauthenticated_route(
            &Method::GET,
            GET_TASK_BY_ID_ROUTE.to_string(),
            GetTaskByIdHandler::new(),
        );

        // --- External Match Routes (v2) --- //
        // If the admin API key is not set, these endpoints are disabled, so a random
        // default is used instead
        let admin_key = config.admin_api_key.unwrap_or_else(HmacKey::random);
        let processor = ExternalMatchProcessor::new(
            admin_key,
            darkpool_client.clone(),
            bus.clone(),
            matching_engine_worker_queue.clone(),
            state.clone(),
        );

        // POST /v2/external-matches/get-quote
        router.add_admin_authenticated_route(
            &Method::POST,
            GET_EXTERNAL_MATCH_QUOTE_ROUTE.to_string(),
            GetExternalMatchQuoteHandler::new(processor.clone()),
        );

        // POST /v2/external-matches/assemble-match-bundle
        router.add_admin_authenticated_route(
            &Method::POST,
            ASSEMBLE_MATCH_BUNDLE_ROUTE.to_string(),
            AssembleMatchBundleHandler::new(processor.clone()),
        );

        // --- Market Routes (v2) --- //

        // GET /v2/markets
        router.add_unauthenticated_route(
            &Method::GET,
            GET_MARKETS_ROUTE.to_string(),
            GetMarketsHandler::new(),
        );

        // GET /v2/markets/depth
        router.add_admin_authenticated_route(
            &Method::GET,
            GET_MARKETS_DEPTH_ROUTE.to_string(),
            GetMarketDepthsHandler::new(),
        );

        // GET /v2/markets/:mint/depth
        router.add_admin_authenticated_route(
            &Method::GET,
            GET_MARKET_DEPTH_BY_MINT_ROUTE.to_string(),
            GetMarketDepthByMintHandler::new(),
        );

        // GET /v2/markets/:mint/price
        router.add_unauthenticated_route(
            &Method::GET,
            GET_MARKET_PRICE_ROUTE.to_string(),
            GetMarketPriceHandler::new(),
        );

        // --- Metadata Routes (v2) --- //

        // GET /v2/metadata/exchange
        router.add_unauthenticated_route(
            &Method::GET,
            GET_EXCHANGE_METADATA_ROUTE.to_string(),
            GetExchangeMetadataHandler::new(state.clone(), darkpool_client.clone()),
        );

        // --- Network Routes (v2) --- //

        // GET /v2/network
        router.add_unauthenticated_route(
            &Method::GET,
            GET_NETWORK_TOPOLOGY_ROUTE.to_string(),
            GetNetworkTopologyHandler::new(config.chain, state.clone()),
        );

        // --- Admin Routes --- //

        // GET /v2/admin/is-leader (preserved)
        router.add_unauthenticated_route(
            &Method::GET,
            IS_LEADER_ROUTE.to_string(),
            IsLeaderHandler::new(state.clone()),
        );

        // POST /v2/admin/trigger-snapshot (preserved)
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_TRIGGER_SNAPSHOT_ROUTE.to_string(),
            AdminTriggerSnapshotHandler::new(state.clone()),
        );

        // POST /v2/admin/refresh-token-mapping (preserved)
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_REFRESH_TOKEN_MAPPING_ROUTE.to_string(),
            AdminRefreshTokenMappingHandler::new(config.chain),
        );

        // POST /v2/admin/refresh-match-fees (preserved)
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_REFRESH_MATCH_FEES_ROUTE.to_string(),
            AdminRefreshMatchFeesHandler::new(config.darkpool_client.clone()),
        );

        // GET /v2/relayer-admin/orders (v2)
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_GET_ORDERS_ROUTE.to_string(),
            AdminGetOrdersHandler::new(state.clone()),
        );

        // GET /v2/relayer-admin/orders/:order_id (v2)
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_GET_ORDER_BY_ID_ROUTE.to_string(),
            AdminGetOrderByIdHandler::new(state.clone()),
        );

        // GET /v2/relayer-admin/account/:account_id/orders
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_GET_ACCOUNT_ORDERS_ROUTE.to_string(),
            AdminGetAccountOrdersHandler::new(state.clone()),
        );

        // GET /v2/relayer-admin/account/:account_id/tasks/paused
        router.add_admin_authenticated_route(
            &Method::GET,
            ADMIN_GET_TASK_QUEUE_PAUSED_ROUTE.to_string(),
            AdminGetTaskQueuePausedHandler::new(state.clone()),
        );

        // --- Matching Pool Routes (v2) --- //

        // POST /v2/admin/matching-pools/:matching_pool
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_MATCHING_POOL_CREATE_ROUTE.to_string(),
            AdminCreateMatchingPoolHandler::new(state.clone()),
        );

        // POST /v2/admin/matching-pools/:matching_pool/destroy
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_MATCHING_POOL_DESTROY_ROUTE.to_string(),
            AdminDestroyMatchingPoolHandler::new(state.clone()),
        );

        // POST /v2/relayer-admin/account/:account_id/orders/create-order-in-pool
        router.add_admin_authenticated_route(
            &Method::POST,
            ADMIN_CREATE_ORDER_IN_POOL_ROUTE.to_string(),
            AdminCreateOrderInPoolHandler::new(executor, state.clone(), task_queue.clone()),
        );

        Ok(router)
    }

    /// The execution loop for the http server, accepts incoming connections,
    /// serves them, and awaits the next connection
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        // Bind to the configured port
        let addr: SocketAddr = format!("0.0.0.0:{}", self.config.http_port)
            .parse()
            .map_err(ApiServerError::server_failure)?;
        let listener = TcpListener::bind(addr).await.map_err(ApiServerError::server_failure)?;

        // Main execution loop
        loop {
            let (stream, _) = listener.accept().await.map_err(ApiServerError::server_failure)?;
            let self_clone = self.clone();
            tokio::spawn(async move { self_clone.handle_stream(stream).await });
        }
    }

    /// Handle an incoming TCP stream from a client
    async fn handle_stream(&self, stream: TcpStream) -> Result<(), ApiServerError> {
        let service_fn = service_fn(move |req: Request<IncomingBody>| {
            let self_clone = self.clone();
            async move {
                let resp = self_clone
                    .router
                    .handle_req(req.method().to_owned(), req.uri().clone(), req)
                    .await;

                Ok::<_, HyperError>(resp)
            }
        });

        // Build an HTTP/1 stream handler and service the connection
        let stream_io = TokioIo::new(stream);
        let timer = TokioTimer::new();
        Http1Builder::new().timer(timer).serve_connection(stream_io, service_fn).await?;

        Ok(())
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
