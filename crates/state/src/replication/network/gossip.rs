//! Gossip networking interface, acts as a shim between raft and our gossip
//! layer

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use gossip_api::request_response::{GossipRequestType, GossipResponse, GossipResponseType};
use job_types::network_manager::{NetworkManagerJob, NetworkManagerQueue};
use openraft::error::{NetworkError, RPCError, RaftError};
use tracing::instrument;

use crate::{
    ciborium_deserialize, ciborium_serialize,
    replication::{
        Node, NodeId,
        error::{ReplicationError, new_network_error},
    },
};

use super::{P2PNetworkFactory, P2PRaftNetwork, P2PRaftNetworkWrapper, RaftRequest, RaftResponse};

/// The error message emitted when a response type is invalid
const ERR_INVALID_RESPONSE: &str = "invalid response type from raft peer";

/// The maximum time to wait for a reply to a raft RPC before failing it as a
/// (recoverable, openraft-retried) network error. An unbounded await here lets a
/// never-answering peer or leader hang the caller -- e.g. a forwarded client
/// write -- indefinitely.
const RAFT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// The number of consecutive send failures to a target after which the
/// circuit breaker opens and subsequent sends fail fast
const BREAKER_FAILURE_THRESHOLD: u32 = 5;

/// The time the circuit breaker stays open before letting a probe through
const BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

/// The error message emitted when the circuit breaker fails a request fast
const ERR_BREAKER_OPEN: &str = "raft RPC failed fast: target circuit breaker open";

// -------------------
// | Circuit Breaker |
// -------------------

/// A circuit breaker tracking consecutive RPC failures to a single raft peer
///
/// Sending to an unreachable peer is expensive for the network stack: each
/// request may hold an outbound dial open until it times out, and openraft
/// retries failed targets roughly once per second. Once a target has failed
/// `BREAKER_FAILURE_THRESHOLD` times in a row, sends fail immediately for
/// `BREAKER_COOLDOWN` without enqueueing a network job.
///
/// The breaker must always eventually let a probe through: after the cooldown
/// expires a single request is admitted to test the target (half-open), and a
/// success fully closes the breaker. This keeps a recovered peer able to
/// rejoin; a permanently open breaker would be a correctness bug.
#[derive(Debug)]
struct CircuitBreaker {
    /// The number of consecutive failures after which the breaker opens
    failure_threshold: u32,
    /// The time the breaker stays open before admitting a probe
    cooldown: Duration,
    /// The current count of consecutive failures
    consecutive_failures: u32,
    /// The time until which requests fail fast, if the breaker is open
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    /// Constructor
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self { failure_threshold, cooldown, consecutive_failures: 0, open_until: None }
    }

    /// Whether a request to the target may proceed
    ///
    /// If the breaker is open and the cooldown has expired, the breaker
    /// re-arms and admits a single probe (half-open); concurrent requests
    /// fail fast until the probe's result is recorded
    pub fn allow_request(&mut self) -> bool {
        match self.open_until {
            None => true,
            Some(deadline) if Instant::now() < deadline => false,
            Some(_) => {
                self.open_until = Some(Instant::now() + self.cooldown);
                true
            },
        }
    }

    /// Record a successful request, closing the breaker
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    /// Record a failed request, opening the breaker once the failure
    /// threshold is reached
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.failure_threshold {
            self.open_until = Some(Instant::now() + self.cooldown);
        }
    }
}

/// The network shim
#[derive(Clone)]
pub struct GossipNetwork {
    /// The target node for this instance
    target: NodeId,
    /// The target node info
    target_info: Node,
    /// The circuit breaker for the target node
    ///
    /// openraft creates one network client per target, so the breaker tracks
    /// consecutive failures to a single peer
    breaker: Arc<Mutex<CircuitBreaker>>,
    /// A sender to the network manager's queue
    network_sender: NetworkManagerQueue,
}

impl GossipNetwork {
    /// Construct a new `GossipNetwork` instance without target specified
    pub fn empty(network_sender: NetworkManagerQueue) -> Self {
        Self {
            target: NodeId::default(),
            target_info: Node::default(),
            breaker: Self::new_breaker(),
            network_sender,
        }
    }

    /// Construct a fresh circuit breaker for a target
    fn new_breaker() -> Arc<Mutex<CircuitBreaker>> {
        Arc::new(Mutex::new(CircuitBreaker::new(BREAKER_FAILURE_THRESHOLD, BREAKER_COOLDOWN)))
    }

    /// Whether the target's circuit breaker allows a request
    fn allow_request(&self) -> bool {
        self.breaker.lock().expect("breaker lock poisoned").allow_request()
    }

    /// Record a successful request in the target's circuit breaker
    fn record_success(&self) {
        self.breaker.lock().expect("breaker lock poisoned").record_success()
    }

    /// Record a failed request in the target's circuit breaker
    fn record_failure(&self) {
        self.breaker.lock().expect("breaker lock poisoned").record_failure()
    }

    /// Convert a gossip response into a raft response
    fn to_raft_response(resp: GossipResponse) -> Result<RaftResponse, ReplicationError> {
        let resp_bytes = match resp.body {
            GossipResponseType::Raft(x) => x,
            _ => {
                return Err(ReplicationError::deserialize(ERR_INVALID_RESPONSE));
            },
        };

        let raft_resp = Self::deserialize_raft_response(&resp_bytes)?;
        Ok(raft_resp)
    }

    /// Deserialize a raft response from bytes
    fn deserialize_raft_response(msg_bytes: &[u8]) -> Result<RaftResponse, ReplicationError> {
        ciborium_deserialize(msg_bytes).map_err(ReplicationError::deserialize)
    }
}

#[async_trait]
impl P2PRaftNetwork for GossipNetwork {
    fn target(&self) -> NodeId {
        self.target
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        name = "send_raft_request", 
        skip_all, err
        fields(req_type = %request.type_str())
    )]
    async fn send_request(
        &self,
        _target: NodeId,
        request: RaftRequest,
    ) -> Result<RaftResponse, RPCError<NodeId, Node, RaftError<NodeId>>> {
        // Fail fast if the target's circuit breaker is open. This is the same
        // recoverable network error as an RPC timeout, so openraft backs off and
        // retries; the breaker admits a probe after its cooldown, allowing a
        // recovered peer to rejoin
        if !self.allow_request() {
            return Err(new_network_error(ReplicationError::Raft(ERR_BREAKER_OPEN.to_string())));
        }

        // We serialize in the raft layer to avoid the `gossip-api` depending on `state`
        let ser =
            ciborium_serialize(&request).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let req = GossipRequestType::Raft(ser);

        // Send a network manager job
        let peer_id = self.target_info.peer_id;
        let (job, rx) = NetworkManagerJob::request_with_response(peer_id, req);
        // A failed send/recv here means the network manager queue is closed or
        // the peer/response channel is gone (teardown, peer loss). That's a
        // recoverable *network* error -- openraft will retry -- NOT a reason to
        // panic, which would take down the raft core (and the node's leadership).
        self.network_sender.send(job).map_err(|_| {
            self.record_failure();
            new_network_error(ReplicationError::Raft(
                "failed to send raft RPC: network manager queue closed".to_string(),
            ))
        })?;

        let resp = match tokio::time::timeout(RAFT_RPC_TIMEOUT, rx).await {
            Ok(res) => res.map_err(|_| {
                self.record_failure();
                new_network_error(ReplicationError::Raft(
                    "raft RPC response channel closed before a reply".to_string(),
                ))
            })?,
            Err(_) => {
                self.record_failure();
                return Err(new_network_error(ReplicationError::Raft(
                    "raft RPC response timed out".to_string(),
                )));
            },
        };

        // Any reply proves the target reachable
        self.record_success();
        Self::to_raft_response(resp).map_err(new_network_error)
    }
}

impl P2PNetworkFactory for GossipNetwork {
    fn new_p2p_client(&self, target: NodeId, target_info: Node) -> P2PRaftNetworkWrapper {
        let mut clone = self.clone();
        clone.target = target;
        clone.target_info = target_info;
        // Give each client its own breaker so the failure count tracks a
        // single target
        clone.breaker = Self::new_breaker();

        P2PRaftNetworkWrapper::new(clone)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::time::{sleep, timeout};

    use super::CircuitBreaker;

    /// The timeout guard applied to each test
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    /// The failure threshold used in tests
    const THRESHOLD: u32 = 3;
    /// The breaker cooldown used in tests
    const COOLDOWN: Duration = Duration::from_millis(20);

    /// Construct a breaker with the test threshold and cooldown
    fn test_breaker() -> CircuitBreaker {
        CircuitBreaker::new(THRESHOLD, COOLDOWN)
    }

    /// Drive a breaker to the open state
    fn open_breaker(breaker: &mut CircuitBreaker) {
        for _ in 0..THRESHOLD {
            breaker.record_failure();
        }
    }

    /// Tests that a closed breaker allows requests, including after failures
    /// below the threshold
    #[tokio::test]
    async fn test_closed_allows_requests() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            assert!(breaker.allow_request());

            for _ in 0..THRESHOLD - 1 {
                breaker.record_failure();
                assert!(breaker.allow_request());
            }
        })
        .await
        .unwrap();
    }

    /// Tests that the breaker opens once the failure threshold is reached
    #[tokio::test]
    async fn test_opens_at_threshold() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            open_breaker(&mut breaker);
            assert!(!breaker.allow_request());
        })
        .await
        .unwrap();
    }

    /// Tests that a success resets the consecutive failure count
    #[tokio::test]
    async fn test_success_resets_failure_count() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            for _ in 0..THRESHOLD - 1 {
                breaker.record_failure();
            }
            breaker.record_success();

            // The count restarts, so another `THRESHOLD - 1` failures keep the
            // breaker closed
            for _ in 0..THRESHOLD - 1 {
                breaker.record_failure();
                assert!(breaker.allow_request());
            }
        })
        .await
        .unwrap();
    }

    /// Tests that an open breaker admits a single probe after the cooldown
    #[tokio::test]
    async fn test_half_open_admits_single_probe() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            open_breaker(&mut breaker);
            sleep(COOLDOWN * 2).await;

            // The first request after the cooldown is the probe; concurrent
            // requests fail fast until the probe's result is recorded
            assert!(breaker.allow_request());
            assert!(!breaker.allow_request());
        })
        .await
        .unwrap();
    }

    /// Tests that a successful probe closes the breaker
    #[tokio::test]
    async fn test_probe_success_closes_breaker() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            open_breaker(&mut breaker);
            sleep(COOLDOWN * 2).await;

            assert!(breaker.allow_request());
            breaker.record_success();
            assert!(breaker.allow_request());
        })
        .await
        .unwrap();
    }

    /// Tests that a failed probe re-opens the breaker for another cooldown,
    /// after which the next probe is admitted
    #[tokio::test]
    async fn test_probe_failure_reopens_breaker() {
        timeout(TEST_TIMEOUT, async {
            let mut breaker = test_breaker();
            open_breaker(&mut breaker);
            sleep(COOLDOWN * 2).await;

            assert!(breaker.allow_request());
            breaker.record_failure();
            assert!(!breaker.allow_request());

            // The breaker must always eventually admit another probe
            sleep(COOLDOWN * 2).await;
            assert!(breaker.allow_request());
        })
        .await
        .unwrap();
    }
}
