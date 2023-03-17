//! Groups handlers for the HTTP API

use async_trait::async_trait;
use crossbeam::channel;
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
use uuid::Uuid;

use crate::{
    api::{
        http::{
            GetExchangeHealthStatesRequest, GetExchangeHealthStatesResponse, GetWalletResponse,
            PingResponse,
        },
        EmptyRequestResponse,
    },
    price_reporter::jobs::PriceReporterManagerJob,
    state::RelayerState,
};

use super::{
    error::ApiServerError,
    router::{Router, TypedHandler, UrlParams},
    worker::ApiServerConfig,
};

/// The :id param in a URL
const ID_URL_PARAM: &str = "id";

// ---------------
// | HTTP Routes |
// ---------------

/// Health check
const PING_ROUTE: &str = "/v0/ping";
/// Exchange health check route
const EXCHANGE_HEALTH_ROUTE: &str = "/v0/exchange/health_check";
/// Returns the wallet information for the given id
const GET_WALLET_ROUTE: &str = "/v0/wallet/:id";

// ----------------
// | Router Setup |
// ----------------

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
            GetWalletHandler::new(global_state),
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

// ----------------
// | Generic APIs |
// ----------------

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
    type Error = ApiServerError;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, Self::Error> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Ok(PingResponse { timestamp })
    }
}

// --------------------------
// | Wallet Operations APIs |
// --------------------------

/// Handler for the GET /wallet/:id route
#[derive(Debug)]
pub struct GetWalletHandler {
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl GetWalletHandler {
    /// Create a new handler for the /v0/wallet/:id route
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for GetWalletHandler {
    type Request = EmptyRequestResponse;
    type Response = GetWalletResponse;
    type Error = ApiServerError;

    async fn handle_typed(
        &self,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, Self::Error> {
        let wallet_id: Uuid = params.get(ID_URL_PARAM).unwrap().parse().unwrap();
        if let Some(wallet) = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
        {
            Ok(GetWalletResponse { wallet })
        } else {
            panic!("implement http error passing from handler")
        }
    }
}

// ------------------------
// | Price Reporting APIs |
// ------------------------

/// Handler for the / route, returns the health report for each individual
/// exchange and the aggregate median
#[derive(Clone, Debug)]
pub(crate) struct ExchangeHealthStatesHandler {
    /// The config for the API server
    config: ApiServerConfig,
}

impl ExchangeHealthStatesHandler {
    /// Create a new handler for "/exchange/health"
    pub fn new(config: ApiServerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TypedHandler for ExchangeHealthStatesHandler {
    type Request = GetExchangeHealthStatesRequest;
    type Response = GetExchangeHealthStatesResponse;
    type Error = ApiServerError;

    async fn handle_typed(
        &self,
        req: Self::Request,
        _params: UrlParams,
    ) -> Result<Self::Response, Self::Error> {
        let (price_reporter_state_sender, price_reporter_state_receiver) = channel::unbounded();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterManagerJob::PeekMedian {
                base_token: req.base_token.clone(),
                quote_token: req.quote_token.clone(),
                channel: price_reporter_state_sender,
            })
            .unwrap();
        let (exchange_connection_state_sender, exchange_connection_state_receiver) =
            channel::unbounded();
        self.config
            .price_reporter_work_queue
            .send(PriceReporterManagerJob::PeekAllExchanges {
                base_token: req.base_token,
                quote_token: req.quote_token,
                channel: exchange_connection_state_sender,
            })
            .unwrap();
        Ok(GetExchangeHealthStatesResponse {
            median: price_reporter_state_receiver.recv().unwrap(),
            all_exchanges: exchange_connection_state_receiver.recv().unwrap(),
        })
    }
}
