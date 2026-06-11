//! Defines the implementation of the `Worker` trait for the ApiServer

use async_trait::async_trait;
use darkpool_client::DarkpoolClient;
use futures::executor::block_on;
use job_types::{
    matching_engine::MatchingEngineWorkerQueue, network_manager::NetworkManagerQueue,
    proof_manager::ProofManagerQueue, task_driver::TaskDriverQueue,
};
use price_state::PriceStreamStates;
use reqwest::Url;
use state::State;
use std::thread::{self, JoinHandle};
use system_bus::SystemBus;
use tokio::{
    runtime::{Builder as TokioBuilder, Runtime},
    task::JoinHandle as TokioJoinHandle,
};
use types_core::{Chain, HmacKey};
use types_runtime::{CancelChannel, Worker};

use super::{
    error::ApiServerError, health::HealthServer, http::HttpServer, websocket::WebsocketServer,
};

/// The number of threads backing the HTTP server
const API_SERVER_NUM_THREADS: usize = 4;

/// Max blocking-pool threads on the api-server runtime (spawned `with_read_tx` /
/// `with_write_tx` state ops behind http/ws handlers). Bounded explicitly below
/// the tokio default 512 so a stuck DB writer cannot grow the pool until the
/// request runtime is starved; generous enough for normal read fan-out.
const API_SERVER_MAX_BLOCKING_THREADS: usize = 256;

/// The number of threads backing the dedicated health server.
///
/// The health server runs on its own runtime so the ELB `/v2/ping` check is
/// answered even when the main api-server runtime is saturated by request load.
const HEALTH_SERVER_NUM_THREADS: usize = 2;

/// Accepts inbound HTTP requests and websocket subscriptions and
/// serves requests from those connections
///
/// Clients of this server might be traders looking to manage their
/// trades, view live execution events, etc
pub struct ApiServer {
    /// The config passed to the worker
    pub(super) config: ApiServerConfig,
    /// The join handle for the http server
    pub(super) http_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The join handle for the websocket server
    pub(super) websocket_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The join handle for the dedicated health server
    pub(super) health_server_join_handle: Option<TokioJoinHandle<ApiServerError>>,
    /// The tokio runtime that the http and websocket servers run inside of
    pub(super) server_runtime: Option<Runtime>,
    /// The dedicated tokio runtime that the health server runs inside of, kept
    /// separate so the ELB health check is never starved by request load
    pub(super) health_runtime: Option<Runtime>,
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        // The coordinator (`#[tokio::main]`) drops workers from within its async
        // context during teardown. A tokio `Runtime`'s default drop does a
        // *blocking* shutdown, which panics when run inside an async context
        // ("Cannot drop a runtime in a context where blocking is not allowed"),
        // turning an orderly teardown into a hard process abort. Tear the
        // runtime down in the background instead -- non-blocking, and safe to
        // call from an async context.
        if let Some(runtime) = self.server_runtime.take() {
            runtime.shutdown_background();
        }
        if let Some(runtime) = self.health_runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// The worker config for the ApiServer
#[derive(Clone)]
pub struct ApiServerConfig {
    /// The port that the HTTP server should listen on
    pub http_port: u16,
    /// The port that the websocket server should listen on
    pub websocket_port: u16,
    /// The port that the dedicated health server should listen on (the ELB
    /// health check targets this port so liveness is independent of request
    /// load on the main HTTP/WS runtime)
    pub health_port: u16,
    /// The admin key, if one is set
    pub admin_api_key: Option<HmacKey>,
    /// The number of tasks per hour a given wallet is allowed to make
    pub wallet_task_rate_limit: u32,
    /// The minimum usdc denominated value for a deposit or withdrawal
    pub min_transfer_amount: f64,
    /// The minimum usdc denominated order size
    pub min_order_size: f64,
    /// The chain that the relayer is running on
    pub chain: Chain,
    /// The URL of the compliance service to use for wallet screening
    ///
    /// Compliance screening is disabled if this is not set
    pub compliance_service_url: Option<Url>,
    /// The list of disabled assets
    pub disabled_assets: Vec<String>,
    /// A handle on the darkpool RPC client
    pub darkpool_client: DarkpoolClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// The price streams from the price reporter
    pub price_streams: PriceStreamStates,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: ProofManagerQueue,
    /// The worker job queue for the MatchingEngineManager
    pub matching_engine_worker_queue: MatchingEngineWorkerQueue,
    /// The task driver queue, used to await task completion
    pub task_queue: TaskDriverQueue,
    /// The relayer-global state
    pub state: State,
    /// The system pubsub bus that all workers have access to
    /// The ApiServer uses this bus to forward internal events onto open
    /// websocket connections
    pub system_bus: SystemBus,
    /// The channel to receive cancellation signals on from the coordinator
    pub cancel_channel: CancelChannel,
}

#[async_trait]
impl Worker for ApiServer {
    type WorkerConfig = ApiServerConfig;
    type Error = ApiServerError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            config,
            http_server_join_handle: None,
            websocket_server_join_handle: None,
            health_server_join_handle: None,
            server_runtime: None,
            health_runtime: None,
        })
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Build a tokio runtime and spawn two blocking tasks; one
        // for the http server, another for the websocket server
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(API_SERVER_NUM_THREADS)
            .max_blocking_threads(API_SERVER_MAX_BLOCKING_THREADS)
            .enable_all()
            .build()
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Build the http server
        let http_server = HttpServer::new(self.config.clone())?;
        let http_thread_handle = tokio_runtime.spawn_blocking(move || {
            let err = block_on(http_server.execution_loop()).err().unwrap();
            ApiServerError::HttpServerFailure(err.to_string())
        });

        // Build the websocket server
        let websocket_server = WebsocketServer::new(self.config.clone());
        let websocket_thread_handle = tokio_runtime.spawn_blocking(move || {
            let err = block_on(websocket_server.execution_loop()).err().unwrap();
            ApiServerError::WebsocketServerFailure(err.to_string())
        });

        // Build a SEPARATE runtime for the health server so the ELB /v2/ping
        // check is answered even when the main runtime above is saturated by
        // request load (the cause of the relayer restart flap).
        let health_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(HEALTH_SERVER_NUM_THREADS)
            .enable_all()
            .build()
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;
        let health_server = HealthServer::new(
            self.config.health_port,
            self.config.http_port,
            self.config.state.clone(),
        );
        let health_thread_handle = health_runtime.spawn_blocking(move || {
            let err = block_on(health_server.execution_loop()).err().unwrap();
            ApiServerError::HttpServerFailure(err.to_string())
        });

        self.http_server_join_handle = Some(http_thread_handle);
        self.websocket_server_join_handle = Some(websocket_thread_handle);
        self.health_server_join_handle = Some(health_thread_handle);
        self.server_runtime = Some(tokio_runtime);
        self.health_runtime = Some(health_runtime);
        Ok(())
    }

    fn name(&self) -> String {
        "api-server".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        // Wrap the Tokio join handle in a wrapper thread
        // TODO: We can probably do this without a wrapper thread
        let join_handle1 = self.http_server_join_handle.take().unwrap();
        let join_handle2 = self.websocket_server_join_handle.take().unwrap();
        let join_handle3 = self.health_server_join_handle.take().unwrap();

        let wrapper1 = thread::spawn(move || block_on(join_handle1).unwrap());
        let wrapper2 = thread::spawn(move || block_on(join_handle2).unwrap());
        let wrapper3 = thread::spawn(move || block_on(join_handle3).unwrap());

        vec![wrapper1, wrapper2, wrapper3]
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        drop(self.server_runtime.take());
        Ok(())
    }
}
