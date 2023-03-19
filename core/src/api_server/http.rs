//! Groups handlers for the HTTP API

use async_trait::async_trait;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error as HyperError, Method, Request, Response, Server,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    external_api::{http::PingResponse, EmptyRequestResponse},
    state::RelayerState,
};

use self::{
    order_book::{GetNetworkOrdersHandler, GET_NETWORK_ORDERS_ROUTE},
    price_report::{ExchangeHealthStatesHandler, EXCHANGE_HEALTH_ROUTE},
    wallet::{
        GetBalanceByMintHandler, GetBalancesHandler, GetFeesHandler, GetOrderByIdHandler,
        GetOrdersHandler, GetWalletHandler, GET_BALANCES_ROUTE, GET_BALANCE_BY_MINT_ROUTE,
        GET_FEES_ROUTE, GET_ORDERS_ROUTE, GET_ORDER_BY_ID_ROUTE, GET_WALLET_ROUTE,
    },
};

use super::{
    error::ApiServerError,
    router::{Router, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

mod order_book;
mod price_report;
mod wallet;

/// Health check
const PING_ROUTE: &str = "/v0/ping";

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
    pub(super) fn new(config: ApiServerConfig, global_state: RelayerState) -> Self {
        // Build the router, server, and register routes
        let router = Self::build_router(&config, global_state);
        Self {
            router: Arc::new(router),
            config,
        }
    }

    /// Build a router and register routes on it
    fn build_router(config: &ApiServerConfig, global_state: RelayerState) -> Router {
        // Build the router and register its routes
        let mut router = Router::new();

        // The "/exchangeHealthStates" route
        router.add_route(
            Method::POST,
            EXCHANGE_HEALTH_ROUTE.to_string(),
            ExchangeHealthStatesHandler::new(config.clone()),
        );

        // The "/ping" route
        router.add_route(Method::GET, PING_ROUTE.to_string(), PingHandler::new());

        // The "/wallet/:id" route
        router.add_route(
            Method::GET,
            GET_WALLET_ROUTE.to_string(),
            GetWalletHandler::new(global_state.clone()),
        );

        // The "/wallet/:id/orders" route
        router.add_route(
            Method::GET,
            GET_ORDERS_ROUTE.to_string(),
            GetOrdersHandler::new(global_state.clone()),
        );

        // The "/wallet/:id/orders/:id" route
        router.add_route(
            Method::GET,
            GET_ORDER_BY_ID_ROUTE.to_string(),
            GetOrderByIdHandler::new(global_state.clone()),
        );

        // The "/wallet/:id/balances" route
        router.add_route(
            Method::GET,
            GET_BALANCES_ROUTE.to_string(),
            GetBalancesHandler::new(global_state.clone()),
        );

        // The "/wallet/:id/balances/:mint" route
        router.add_route(
            Method::GET,
            GET_BALANCE_BY_MINT_ROUTE.to_string(),
            GetBalanceByMintHandler::new(global_state.clone()),
        );

        // The "/wallet/:id/fees" route
        router.add_route(
            Method::GET,
            GET_FEES_ROUTE.to_string(),
            GetFeesHandler::new(global_state.clone()),
        );

        // The "/order_book/orders" route
        router.add_route(
            Method::GET,
            GET_NETWORK_ORDERS_ROUTE.to_string(),
            GetNetworkOrdersHandler::new(global_state),
        );

        router
    }

    /// The execution loop for the http server, accepts incoming connections, serves them,
    /// and awaits the next connection
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
        let addr: SocketAddr = format!("0.0.0.0:{}", self.config.http_port)
            .parse()
            .unwrap();
        Server::bind(&addr)
            .serve(make_service)
            .await
            .map_err(|err| ApiServerError::HttpServerFailure(err.to_string()))
    }

    /// Serve an http request
    async fn serve_request(&self, req: Request<Body>) -> Response<Body> {
        self.router
            .handle_req(req.method().to_owned(), req.uri().path().to_string(), req)
            .await
    }
}

/// Handler for the ping route, returns a pong
#[derive(Clone, Debug)]
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
        _req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Ok(PingResponse { timestamp })
    }
}
