//! Defines the implementation of the `Worker` trait for the ApiServer

use async_trait::async_trait;
use common::{
    types::{gossip::SymmetricAuthKey, CancelChannel},
    worker::Worker,
};
use external_api::bus_message::SystemBusMessage;
use futures::executor::block_on;
use job_types::{
    handshake_manager::HandshakeManagerQueue, network_manager::NetworkManagerQueue,
    price_reporter::PriceReporterQueue, proof_manager::ProofManagerQueue,
};
use state::State;
use std::thread::{self, JoinHandle};
use system_bus::SystemBus;
use tokio::{
    runtime::{Builder as TokioBuilder, Runtime},
    task::JoinHandle as TokioJoinHandle,
};

use super::{error::ApiServerError, http::HttpServer, websocket::WebsocketServer};

/// The number of threads backing the HTTP server
const API_SERVER_NUM_THREADS: usize = 4;

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
    /// The tokio runtime that the http server runs inside of
    pub(super) server_runtime: Option<Runtime>,
}

/// The worker config for the ApiServer
#[derive(Clone)]
pub struct ApiServerConfig {
    /// The port that the HTTP server should listen on
    pub http_port: u16,
    /// The port that the websocket server should listen on
    pub websocket_port: u16,
    /// The admin key, if one is set
    pub admin_api_key: Option<SymmetricAuthKey>,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// The worker job queue for the PriceReporter
    pub price_reporter_work_queue: PriceReporterQueue,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: ProofManagerQueue,
    /// The worker job queue for the HandshakeManager
    pub handshake_manager_work_queue: HandshakeManagerQueue,
    /// The relayer-global state
    pub state: State,
    /// The system pubsub bus that all workers have access to
    /// The ApiServer uses this bus to forward internal events onto open
    /// websocket connections
    pub system_bus: SystemBus<SystemBusMessage>,
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
            server_runtime: None,
        })
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Build a tokio runtime and spawn two blocking tasks; one
        // for the http server, another for the websocket server
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(API_SERVER_NUM_THREADS)
            .enable_all()
            .build()
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;

        // Build the http server
        let http_server = HttpServer::new(self.config.clone(), self.config.state.clone());
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

        self.http_server_join_handle = Some(http_thread_handle);
        self.websocket_server_join_handle = Some(websocket_thread_handle);
        self.server_runtime = Some(tokio_runtime);
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

        let wrapper1 = thread::spawn(move || block_on(join_handle1).unwrap());
        let wrapper2 = thread::spawn(move || block_on(join_handle2).unwrap());

        vec![wrapper1, wrapper2]
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        drop(self.server_runtime.take());
        Ok(())
    }
}
