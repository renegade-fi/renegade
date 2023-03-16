//! Groups handlers for the HTTP API

use async_trait::async_trait;
use circuits::types::fee::Fee;
use crossbeam::channel::{self, Sender};
use crypto::fields::biguint_to_scalar;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error as HyperError, Method, Request, Response, Server,
};
use itertools::Itertools;
use std::{
    convert::Infallible,
    iter,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot::channel as oneshot_channel;

use crate::{
    api::http::{
        CreateWalletRequest, GetExchangeHealthStatesRequest, GetExchangeHealthStatesResponse,
        GetReplicasRequest, GetReplicasResponse, PingRequest, PingResponse,
    },
    price_reporter::jobs::PriceReporterManagerJob,
    proof_generation::jobs::{ProofJob, ProofManagerJob},
    state::RelayerState,
    MAX_FEES,
};

use super::{
    error::ApiServerError,
    router::{Router, TypedHandler},
    worker::ApiServerConfig,
};

// ---------------
// | HTTP Routes |
// ---------------

/// Health check
const PING_ROUTE: &str = "/ping";
/// Exchange health check route
const EXCHANGE_HEALTH_ROUTE: &str = "/exchange/health_check";
/// Returns the replicating nodes of a given wallet
const REPLICAS_ROUTE: &str = "/replicas";
/// Creates a new wallet with the given fees and keys and submits it to the contract
const WALLET_CREATE_ROUTE: &str = "/wallet/create";

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

        // The "/replicas" route
        router.add_route(
            Method::POST,
            REPLICAS_ROUTE.to_string(),
            ReplicasHandler::new(global_state),
        );

        // The "/wallet/create" route
        router.add_route(
            Method::POST,
            WALLET_CREATE_ROUTE.to_string(),
            WalletCreateHandler::new(config.proof_generation_work_queue.clone()),
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
    type Request = PingRequest;
    type Response = PingResponse;
    type Error = ApiServerError;

    async fn handle_typed(&self, _req: Self::Request) -> Result<Self::Response, Self::Error> {
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

/// Handler for the /wallet/create route
#[derive(Debug)]
pub struct WalletCreateHandler {
    /// The channel to enqueue a proof generation request of `VALID WALLET CREATE` on
    proof_job_queue: Sender<ProofManagerJob>,
}

impl WalletCreateHandler {
    /// Create a new handler for the /wallet/create route
    pub fn new(proof_manager_job_queue: Sender<ProofManagerJob>) -> Self {
        Self {
            proof_job_queue: proof_manager_job_queue,
        }
    }
}

#[async_trait]
impl TypedHandler for WalletCreateHandler {
    type Request = CreateWalletRequest;
    type Response = (); // TODO: Define a response type
    type Error = ApiServerError;

    async fn handle_typed(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        // Pad the fees to be of length MAX_FEES
        let fees_padded = req
            .fees
            .into_iter()
            .chain(iter::repeat(Fee::default()))
            .take(MAX_FEES)
            .collect_vec();

        // Forward a request to the proof generation module to build a proof of
        // `VALID WALLET CREATE`
        let (response_sender, response_receiver) = oneshot_channel();
        self.proof_job_queue
            .send(ProofManagerJob {
                type_: ProofJob::ValidWalletCreate {
                    fees: fees_padded,
                    keys: req.keys.into(),
                    randomness: biguint_to_scalar(&req.randomness),
                },
                response_channel: response_sender,
            })
            .map_err(|err| ApiServerError::EnqueueJob(err.to_string()))?;

        // Await a response
        let resp = response_receiver.await.unwrap();
        println!("got proof back: {:?}", resp);
        Ok(())
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

    async fn handle_typed(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
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

// ---------------------
// | Cluster Info APIs |
// ---------------------

/// Handler for the replicas route, returns the number of replicas a given wallet has
#[derive(Clone, Debug)]
pub struct ReplicasHandler {
    /// The global state of the relayer, used to query information for requests
    global_state: RelayerState,
}

impl ReplicasHandler {
    /// Create a new handler for "/replicas"
    pub fn new(global_state: RelayerState) -> Self {
        Self { global_state }
    }
}

#[async_trait]
impl TypedHandler for ReplicasHandler {
    type Request = GetReplicasRequest;
    type Response = GetReplicasResponse;
    type Error = ApiServerError;

    async fn handle_typed(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        let replicas = if let Some(wallet_info) = self
            .global_state
            .read_wallet_index()
            .await
            .read_wallet(&req.wallet_id)
            .await
        {
            wallet_info.metadata.replicas.clone().into_iter().collect()
        } else {
            vec![]
        };

        Ok(GetReplicasResponse { replicas })
    }
}
