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
//! The handler does one cheap, non-blocking thing beyond replying: it reads the
//! raft readiness signal (`State::is_raft_ready`, a lock-free read of the raft
//! metrics watch channel) and answers 200 only when this node is an adopted,
//! replicating cluster member. A node that is up but not in the leader's
//! membership (still joining, or dropped out after a leader restart) answers 503
//! so the ELB drains it, instead of staying in rotation and serving requests it
//! cannot complete -- which surface to clients as 504 Gateway Timeouts. A
//! busy-but-adopted node still answers 200 promptly because this runtime is not
//! starved by request load, preserving the anti-flap property above.

use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{
    Error as HyperError, Request, Response, StatusCode,
    body::{Bytes as BytesBody, Incoming as IncomingBody},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use state::State;
use tokio::net::{TcpListener, TcpStream};
use util::get_current_time_millis;

use crate::error::ApiServerError;

/// A minimal HTTP server that answers the ELB health check on a dedicated port.
#[derive(Clone)]
pub struct HealthServer {
    /// The port the health server listens on
    port: u16,
    /// Handle on global state, used to report raft readiness so the ELB drains a
    /// node that is up but not an adopted, replicating cluster member.
    state: State,
}

impl HealthServer {
    /// Create a new health server bound to the given port
    pub fn new(port: u16, state: State) -> Self {
        Self { port, state }
    }

    /// Accept connections and answer the health check, forever
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        let addr: SocketAddr =
            format!("0.0.0.0:{}", self.port).parse().map_err(ApiServerError::server_failure)?;
        let listener = TcpListener::bind(addr).await.map_err(ApiServerError::server_failure)?;

        loop {
            let (stream, _) = listener.accept().await.map_err(ApiServerError::server_failure)?;
            let state = self.state.clone();
            tokio::spawn(async move {
                let _ = Self::handle_stream(stream, state).await;
            });
        }
    }

    /// Serve a single connection, replying 200 when this node is a ready raft
    /// member and 503 otherwise so the load balancer drains an unready node
    async fn handle_stream(stream: TcpStream, state: State) -> Result<(), ApiServerError> {
        let service = service_fn(move |_req: Request<IncomingBody>| {
            let state = state.clone();
            async move {
                let ready = state.is_raft_ready();
                let status =
                    if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
                let body =
                    format!("{{\"timestamp\":{},\"ready\":{ready}}}", get_current_time_millis());
                let resp = Response::builder()
                    .status(status)
                    .body(Full::new(BytesBody::from(body)))
                    .expect("building the health response cannot fail");
                Ok::<_, HyperError>(resp)
            }
        });

        let stream_io = TokioIo::new(stream);
        let timer = TokioTimer::new();
        Http1Builder::new().timer(timer).serve_connection(stream_io, service).await?;
        Ok(())
    }
}
