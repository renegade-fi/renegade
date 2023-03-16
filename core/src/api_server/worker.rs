//! Defines the implementation of the `Worker` trait for the ApiServer

use crossbeam::channel::Sender as CrossbeamSender;
use futures::executor::block_on;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error, Request, Server,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    thread::{self, JoinHandle},
};
use tokio::{runtime::Builder as TokioBuilder, sync::mpsc::UnboundedSender as TokioSender};

use crate::{
    price_reporter::jobs::PriceReporterManagerJob, proof_generation::jobs::ProofManagerJob,
    state::RelayerState, system_bus::SystemBus, types::SystemBusMessage, worker::Worker,
    CancelChannel,
};

use super::{error::ApiServerError, router::Router, server::ApiServer};

/// The number of threads backing the HTTP server
const API_SERVER_NUM_THREADS: usize = 2;

/// The worker config for the ApiServer
#[derive(Clone, Debug)]
pub struct ApiServerConfig {
    /// The port that the HTTP server should listen on
    pub http_port: u16,
    /// The port that the websocket server should listen on
    pub websocket_port: u16,
    /// The worker job queue for the PriceReporterManager
    pub price_reporter_work_queue: TokioSender<PriceReporterManagerJob>,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The relayer-global state
    pub global_state: RelayerState,
    /// The system pubsub bus that all workers have access to
    /// The ApiServer uses this bus to forward internal events onto open
    /// websocket connections
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The channel to receive cancellation signals on from the coordinator
    pub cancel_channel: CancelChannel,
}

impl Worker for ApiServer {
    type WorkerConfig = ApiServerConfig;
    type Error = ApiServerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        // Build the http server
        let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse().unwrap();
        let builder = Server::bind(&addr);

        Ok(Self {
            config,
            http_server_builder: Some(builder),
            http_server_join_handle: None,
            websocket_server_join_handle: None,
            server_runtime: None,
        })
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Take ownership of the http server, begin listening
        let server_builder = self.http_server_builder.take().unwrap();

        // Build the routes for the HTTP server
        let mut router = Router::new();
        Self::setup_routes(
            &mut router,
            self.config.clone(),
            self.config.global_state.clone(),
        );

        let shared_router = Arc::new(router);

        // Clone the global state and move it into each layer of the callback so that each
        // scope has its own copy of the global state
        let make_service = make_service_fn(move |_: &AddrStream| {
            let shared_router = shared_router.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let shared_router = shared_router.clone();
                    async move { Ok::<_, Error>(Self::handle_http_req(req, shared_router).await) }
                }))
            }
        });

        // Spawn a tokio thread pool to run the server in
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(API_SERVER_NUM_THREADS)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;
        let http_thread_handle = tokio_runtime.spawn_blocking(move || {
            let server = server_builder.serve(make_service);
            if let Err(err) = block_on(server) {
                return ApiServerError::HttpServerFailure(err.to_string());
            }
            ApiServerError::HttpServerFailure("http server spuriously shut down".to_string())
        });

        // Start up the websocket server
        let addr: SocketAddr = format!("0.0.0.0:{:?}", self.config.websocket_port)
            .parse()
            .unwrap();

        let system_bus_clone = self.config.system_bus.clone();
        let price_reporter_work_queue_clone = self.config.price_reporter_work_queue.clone();
        let websocket_thread_handle = tokio_runtime.spawn_blocking(move || {
            block_on(async {
                if let Err(err) = Self::websocket_execution_loop(
                    addr,
                    price_reporter_work_queue_clone,
                    system_bus_clone,
                )
                .await
                {
                    return ApiServerError::WebsocketServerFailure(err.to_string());
                }

                ApiServerError::WebsocketServerFailure(
                    "websocket server spuriously shut down".to_string(),
                )
            })
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
