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
//! The handler answers 200 only when BOTH conditions hold:
//!   1. Raft readiness (`State::is_raft_ready`, a lock-free read of the raft
//!      metrics watch channel): this node is an adopted, replicating member. A
//!      node that is up but not in the leader's membership (still joining, or
//!      dropped after a leader restart) answers 503 so the ELB drains it instead
//!      of staying in rotation and 504ing the requests routed to it.
//!   2. Main-runtime liveness: a bounded self-probe (a short-timeout HTTP GET to
//!      the main server's `/v2/network` on `127.0.0.1`) succeeds. The main
//!      api-server runtime can wedge (an unbounded await/lock starving its worker
//!      threads, or a stalled shared state read) while raft stays healthy on its
//!      own runtime -- so raft readiness ALONE does not prove the node can serve.
//!      If the self-probe times out, the main runtime is wedged; we answer 503 so
//!      the ELB fails the check and ECS restarts the task, restoring the self-heal
//!      that the dedicated health runtime would otherwise mask.
//!
//! Because this health runtime is separate and near-idle, neither the readiness
//! read nor the self-probe is starved by request load, so a busy-but-healthy node
//! still answers 200 promptly -- preserving the anti-flap property above; only a
//! real wedge (or a real loss of membership) trips the 503.

use std::{net::SocketAddr, time::Duration};

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

/// Timeout for the self-probe of the main HTTP server. Kept well under the ELB
/// health-check timeout so a wedged main runtime is reported as 503 within a
/// single check, but long enough that normal request latency never trips it.
const MAIN_SERVER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// A minimal HTTP server that answers the ELB health check on a dedicated port.
#[derive(Clone)]
pub struct HealthServer {
    /// The port the health server listens on
    port: u16,
    /// The port the main HTTP server listens on, self-probed to detect a wedged
    /// request-serving runtime (see module docs).
    http_port: u16,
    /// Handle on global state, used to report raft readiness so the ELB drains a
    /// node that is up but not an adopted, replicating cluster member.
    state: State,
    /// HTTP client used to self-probe the main server. A bounded request that
    /// errors or times out means the main request-serving runtime is wedged.
    probe_client: reqwest::Client,
}

impl HealthServer {
    /// Create a new health server bound to `port` that self-probes the main HTTP
    /// server on `http_port`
    pub fn new(port: u16, http_port: u16, state: State) -> Self {
        let probe_client = reqwest::Client::builder()
            .timeout(MAIN_SERVER_PROBE_TIMEOUT)
            .build()
            .expect("building the health probe client cannot fail");
        Self { port, http_port, state, probe_client }
    }

    /// Accept connections and answer the health check, forever
    pub async fn execution_loop(self) -> Result<(), ApiServerError> {
        let addr: SocketAddr =
            format!("0.0.0.0:{}", self.port).parse().map_err(ApiServerError::server_failure)?;
        let listener = TcpListener::bind(addr).await.map_err(ApiServerError::server_failure)?;

        loop {
            let (stream, _) = listener.accept().await.map_err(ApiServerError::server_failure)?;
            let server = self.clone();
            tokio::spawn(async move {
                let _ = server.handle_stream(stream).await;
            });
        }
    }

    /// Serve a single connection, replying 200 only when this node is both a
    /// ready raft member AND its main request-serving runtime answers a bounded
    /// self-probe; 503 otherwise so the load balancer drains (and ECS recycles)
    /// an unready or wedged node.
    async fn handle_stream(self, stream: TcpStream) -> Result<(), ApiServerError> {
        let state = self.state.clone();
        let probe_client = self.probe_client.clone();
        let http_port = self.http_port;
        let service = service_fn(move |_req: Request<IncomingBody>| {
            let state = state.clone();
            let probe_client = probe_client.clone();
            async move {
                let raft_ready = state.is_raft_ready();
                // Only probe once adopted: before then the main server has not
                // bound its port yet, so a failed probe would be expected noise.
                let serving = if raft_ready {
                    let url = format!("http://127.0.0.1:{http_port}/v2/network");
                    // Any HTTP response (even an error status) proves the main
                    // runtime is making progress; a timeout/error means it is wedged.
                    probe_client.get(url).send().await.is_ok()
                } else {
                    false
                };
                let ok = raft_ready && serving;
                let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
                let body = format!(
                    "{{\"timestamp\":{},\"ready\":{raft_ready},\"serving\":{serving}}}",
                    get_current_time_millis()
                );
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
