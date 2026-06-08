//! A minimal health server, bound to a dedicated port and driven by its OWN
//! tokio runtime, so the ELB `/v2/ping` health check is always answerable
//! regardless of how saturated the main request-serving runtime is.
//!
//! The main HTTP/WS api-server shares a single (4-worker-thread) runtime across
//! the accept loop and every request handler. Under load (quoter +
//! external-match flood) those threads can stay saturated long enough that even
//! the trivial `/v2/ping` handler is not polled within the ELB timeout; ECS
//! then SIGKILLs the task for "failed ELB health checks" though it is otherwise
//! working, producing a restart flap. Serving the health check from a separate,
//! near-idle runtime decouples liveness from request load and stops the flap.
//!
//! This server touches no state, locks, queues, or auth -- it answers every
//! request with a 200, exactly like the in-router `PingHandler`, but cannot be
//! starved by handler work.

use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{
    Error as HyperError, Request, Response, StatusCode,
    body::{Bytes as BytesBody, Incoming as IncomingBody},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use util::get_current_time_millis;

use crate::error::ApiServerError;

/// A minimal HTTP server that answers the ELB health check on a dedicated port.
#[derive(Clone)]
pub struct HealthServer {
    /// The port the health server listens on
    port: u16,
}

impl HealthServer {
    /// Create a new health server bound to the given port
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Accept connections and answer every request with a 200, forever
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        let addr: SocketAddr =
            format!("0.0.0.0:{}", self.port).parse().map_err(ApiServerError::server_failure)?;
        let listener = TcpListener::bind(addr).await.map_err(ApiServerError::server_failure)?;

        loop {
            let (stream, _) = listener.accept().await.map_err(ApiServerError::server_failure)?;
            tokio::spawn(async move {
                let _ = Self::handle_stream(stream).await;
            });
        }
    }

    /// Serve a single connection, replying 200 to any request
    async fn handle_stream(stream: TcpStream) -> Result<(), ApiServerError> {
        let service = service_fn(|_req: Request<IncomingBody>| async move {
            let body = format!("{{\"timestamp\":{}}}", get_current_time_millis());
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(BytesBody::from(body)))
                .expect("building a static 200 response cannot fail");
            Ok::<_, HyperError>(resp)
        });

        let stream_io = TokioIo::new(stream);
        let timer = TokioTimer::new();
        Http1Builder::new().timer(timer).serve_connection(stream_io, service).await?;
        Ok(())
    }
}
