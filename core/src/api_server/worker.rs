//! Defines the implementation of the `Worker` trait for the ApiServer

use std::{
    convert::Infallible,
    net::SocketAddr,
    thread::{self, JoinHandle},
};

use futures::executor::block_on;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Error, Request, Response, Server,
};
use tokio::runtime::Builder as TokioBuilder;

use crate::worker::Worker;

use super::{error::ApiServerError, server::ApiServer};

/// The number of threads backing the HTTP server
const HTTP_SERVER_NUM_THREADS: usize = 1;

/// The worker config for the ApiServer
#[derive(Clone, Debug)]
pub struct ApiServerConfig {
    /// The port that the HTTP server should listen on
    pub http_port: u16,
}

impl Worker for ApiServer {
    type WorkerConfig = ApiServerConfig;
    type Error = ApiServerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        // Build the http server
        let addr: SocketAddr = format!("127.0.0.1:{}", config.http_port).parse().unwrap();
        let builder = Server::bind(&addr);

        Ok(Self {
            http_server_builder: Some(builder),
            http_server_join_handle: None,
            http_server_runtime: None,
        })
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Take ownership of the http server, begin listening
        let server_builder = self.http_server_builder.take().unwrap();
        let make_service = make_service_fn(|_: &AddrStream| async {
            Ok::<_, Infallible>(service_fn(|_req: Request<Body>| async move {
                let response = Response::new(Body::from("Test response"));
                Ok::<_, Error>(response)
            }))
        });

        // Spawn a tokio thread pool to run the server in
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(HTTP_SERVER_NUM_THREADS)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| ApiServerError::Setup(err.to_string()))?;
        let thread_handle = tokio_runtime.spawn_blocking(move || {
            let server = server_builder.serve(make_service);
            if let Err(err) = block_on(server) {
                return ApiServerError::HttpServerFailure(err.to_string());
            }
            ApiServerError::HttpServerFailure("http server spuriously shut down".to_string())
        });

        self.http_server_join_handle = Some(thread_handle);
        self.http_server_runtime = Some(tokio_runtime);

        Ok(())
    }

    fn name(&self) -> String {
        "api-server".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        // Wrap the Tokio join handle in a wrapper thread
        let join_handle = self.http_server_join_handle.take().unwrap();
        let wrapper = thread::spawn(move || block_on(join_handle).unwrap());
        vec![wrapper]
    }

    fn is_recoverable(&self) -> bool {
        true
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }
}
