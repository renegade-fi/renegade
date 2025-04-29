//! The gossip server manages the general gossip network interaction of a single
//! p2p node
//!
//! This file groups logic for creating the server as well as the central
//! dispatch/execution loop of the workers

use common::{
    default_wrapper::DefaultWrapper,
    types::{gossip::WrappedPeerId, CancelChannel},
};
use constants::in_bootstrap_mode;
use darkpool_client::client::DarkpoolClient;
use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        PubsubMessage,
    },
    request_response::{
        heartbeat::BootstrapRequest, GossipRequest, GossipRequestType, GossipResponse,
        GossipResponseType,
    },
};
use job_types::{
    gossip_server::{GossipServerJob, GossipServerQueue, GossipServerReceiver},
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
};
use state::State;
use std::{
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tracing::{error, info, instrument, warn};
use util::err_str;

use crate::peer_discovery::{
    expiry_window::PeerExpiryWindows,
    heartbeat::{CLUSTER_HEARTBEAT_INTERVAL_MS, HEARTBEAT_INTERVAL_MS},
    heartbeat_timer::HeartbeatTimer,
};

use super::{errors::GossipError, worker::GossipServerConfig};

/// The number of threads backing the gossip executor's thread pool
pub(super) const GOSSIP_EXECUTOR_N_THREADS: usize = 5;
/// The number of threads backing the blocking thread pool of the executor
pub(super) const GOSSIP_EXECUTOR_N_BLOCKING_THREADS: usize = 5;
/// The job execution latency at which we log a warning
pub(super) const GOSSIP_JOB_LATENCY_WARNING_MS: Duration = Duration::from_millis(100);

/// The server type that manages interactions with the gossip network
pub struct GossipServer {
    /// The config for the Gossip Server
    pub(super) config: GossipServerConfig,
    /// The protocol executor, handles request/response for the gossip protocol
    pub(super) protocol_executor_handle: Option<JoinHandle<GossipError>>,
}

impl GossipServer {
    /// Get a reference to the global state
    pub fn state(&self) -> &State {
        &self.config.global_state
    }

    /// Bootstraps the local node into the network by syncing state with known
    /// bootstrap peers and then advertising the local node's presence to the
    /// cluster
    pub async fn bootstrap_into_network(&self) -> Result<(), GossipError> {
        // Bootstrap into the network in two steps:
        //  1. Forward all bootstrap addresses to the network manager so it may dial
        //     them
        //  2. Send bootstrap requests to all bootstrapping peers
        //  3. Send heartbeats to all peers for state sync
        // Wait until all peers have been indexed before sending requests to give async
        // network manager time to index the peers in the case that these
        // messages are processed concurrently

        // 1. Forward bootstrap addresses to the network manager
        for (peer_id, address) in self.config.bootstrap_servers.iter().cloned() {
            let cmd = NetworkManagerControlSignal::NewAddr { peer_id, address };
            let job = NetworkManagerJob::internal(cmd);

            self.config.network_sender.send(job).map_err(err_str!(GossipError::SendMessage))?;
        }

        // 2. Send bootstrap requests to all known peers
        let my_id = self.config.local_peer_id;
        let my_info = self.state().get_peer_info(&my_id).await?.unwrap();
        let req = GossipRequestType::Bootstrap(BootstrapRequest { peer_info: my_info });
        for (peer_id, _) in self.config.bootstrap_servers.iter() {
            let req = NetworkManagerJob::request(*peer_id, req.clone());
            self.config.network_sender.send(req).map_err(err_str!(GossipError::SendMessage))?;
        }

        // 3. Send heartbeats to all known peers to sync state
        let peer_ids = self.state().get_all_peers_ids(false /* include_self */).await?;
        for peer in peer_ids.into_iter() {
            self.config
                .job_sender
                .send(GossipServerJob::ExecuteHeartbeat(peer))
                .map_err(err_str!(GossipError::SendMessage))?;
        }

        Ok(())
    }
}

// ---------------------
// | Protocol Executor |
// ---------------------

/// Executes the heartbeat protocols
#[derive(Clone)]
pub struct GossipProtocolExecutor {
    /// The peer expiry cache; maintains the state of peers that are in the
    /// process of being expired or have been expired and are marked as
    /// "invisible"
    pub expiry_buffer: PeerExpiryWindows,
    /// The channel on which to receive jobs
    pub job_receiver: DefaultWrapper<Option<GossipServerReceiver>>,
    /// The channel to send outbound network requests on
    pub network_channel: NetworkManagerQueue,
    /// The global state of the relayer
    pub state: State,
    /// A copy of the config passed to the worker
    pub config: GossipServerConfig,
    /// The channel that the coordinator thread uses to cancel gossip execution
    pub cancel_channel: CancelChannel,
}

impl GossipProtocolExecutor {
    /// Creates a new executor
    pub fn new(
        network_channel: NetworkManagerQueue,
        job_receiver: GossipServerReceiver,
        state: State,
        config: GossipServerConfig,
        cancel_channel: CancelChannel,
    ) -> Result<Self, GossipError> {
        // Tracks recently expired peers and blocks them from being re-registered
        // until the state has synced. Maps peer_id to expiry time
        let expiry_buffer = PeerExpiryWindows::new();

        Ok(Self {
            expiry_buffer,
            job_receiver: DefaultWrapper::new(Some(job_receiver)),
            network_channel,
            state,
            config,
            cancel_channel,
        })
    }

    /// Shorthand to fetch the darkpool client from the config
    pub(super) fn darkpool_client(&self) -> &DarkpoolClient {
        &self.config.darkpool_client
    }

    /// Runs the executor loop
    pub async fn execution_loop(
        mut self,
        job_sender: GossipServerQueue,
    ) -> Result<(), GossipError> {
        info!("Starting executor loop for heartbeat protocol executor...");

        // Start a timer to enqueue outbound heartbeats
        HeartbeatTimer::new(
            job_sender,
            CLUSTER_HEARTBEAT_INTERVAL_MS,
            HEARTBEAT_INTERVAL_MS,
            self.state.clone(),
        );

        // We check for cancels both before receiving a job (so that we don't sleep
        // after cancellation) and after a receiving a job (so that we avoid
        // unnecessary work)
        let mut job_receiver = self.job_receiver.take().unwrap();
        loop {
            tokio::select! {
                // Await the next job
                Some(job) = job_receiver.recv() => {
                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_job(job).await {
                            error!("error handling gossip server job: {e}");
                        }
                    });
                },

                // Await a cancel signal from the coordinator
                _ = self.cancel_channel.changed() => {
                    info!("Gossip server cancelled, shutting down...");
                    return Err(GossipError::Cancelled("server cancelled".to_string()));
                }
            }
        }
    }

    /// The main dispatch method for handling jobs
    #[instrument(name = "gossip_server_job", skip(self))]
    async fn handle_job(&self, job: GossipServerJob) -> Result<(), GossipError> {
        let start = Instant::now();
        match job {
            GossipServerJob::ExecuteHeartbeat(peer_id) => self.send_heartbeat(peer_id).await?,
            GossipServerJob::NetworkRequest(peer_id, req, response_chan) => {
                let resp = self.handle_request(peer_id, req).await?;
                let job = NetworkManagerJob::response(resp, response_chan);

                self.network_channel.send(job).map_err(err_str!(GossipError::SendMessage))?;
            },
            GossipServerJob::NetworkResponse(peer_id, resp) => {
                self.handle_response(peer_id, resp).await?
            },
            GossipServerJob::Pubsub(sender, msg) => self.handle_pubsub(sender, msg).await?,
        };

        // Log slow jobs
        let elapsed = start.elapsed();
        if start.elapsed() > GOSSIP_JOB_LATENCY_WARNING_MS {
            warn!("gossip server job took {elapsed:.2?}");
        }

        Ok(())
    }

    /// Handles a gossip request type from a peer
    #[instrument(name = "handle_request", skip(self, req))]
    async fn handle_request(
        &self,
        peer: WrappedPeerId,
        req: GossipRequest,
    ) -> Result<GossipResponseType, GossipError> {
        if should_ignore_request(&req) {
            return Ok(GossipResponseType::Ack);
        }

        match req.body {
            GossipRequestType::Bootstrap(req) => self.handle_bootstrap_req(req).await,
            GossipRequestType::Heartbeat(req) => {
                self.handle_heartbeat(&peer, &req).await?;
                Ok(GossipResponseType::Ack)
            },
            GossipRequestType::PeerInfo(req) => self.handle_peer_info_req(req.peer_ids).await,
            GossipRequestType::OrderInfo(req) => {
                self.handle_order_info_request(&req.order_ids).await
            },
            req => Err(GossipError::UnhandledRequest(format!("{req:?}"))),
        }
    }

    /// Handles a gossip response type from a peer
    #[instrument(name = "handle_response", skip(self, resp))]
    async fn handle_response(
        &self,
        peer: WrappedPeerId,
        resp: GossipResponse,
    ) -> Result<(), GossipError> {
        if should_ignore_response(&resp) {
            return Ok(());
        }

        match resp.body {
            GossipResponseType::Heartbeat(resp) => self.handle_heartbeat(&peer, &resp).await,
            GossipResponseType::OrderInfo(resp) => {
                self.handle_order_info_response(resp.order_info).await
            },
            GossipResponseType::PeerInfo(resp) => self.handle_peer_info_resp(resp.peer_info).await,
            resp => Err(GossipError::UnhandledRequest(format!("{resp:?}"))),
        }
    }

    /// Handles an inbound pubsub message from the network
    #[instrument(name = "handle_pubsub", skip(self, msg))]
    async fn handle_pubsub(
        &self,
        sender: WrappedPeerId,
        msg: PubsubMessage,
    ) -> Result<(), GossipError> {
        if should_ignore_pubsub(&msg) {
            return Ok(());
        }

        match msg {
            PubsubMessage::Orderbook(msg) => self.handle_orderbook_pubsub(msg).await,
            PubsubMessage::Cluster(ClusterManagementMessage { message_type, .. }) => {
                match message_type {
                    ClusterManagementMessageType::ProposeExpiry(peer_id) => {
                        self.handle_propose_expiry(sender, peer_id).await
                    },
                    ClusterManagementMessageType::RejectExpiry { peer_id, last_heartbeat } => {
                        self.handle_reject_expiry(sender, peer_id, last_heartbeat).await
                    },
                    _ => Err(GossipError::UnhandledRequest(format!("{message_type:?}"))),
                }
            },
        }
    }
}

// -----------
// | Helpers |
// -----------

/// Whether or not the relayer should ignore a request
fn should_ignore_request(req: &GossipRequest) -> bool {
    // Only bootstrap mode currently causes requests to be ignored
    if !in_bootstrap_mode() {
        return false;
    }

    // We intentionally do not have a default case here so that when new request
    // types are added, we will remember to update this function
    match req.body {
        GossipRequestType::Handshake(_) | GossipRequestType::OrderInfo(_) => true,
        GossipRequestType::Ack
        | GossipRequestType::Bootstrap(_)
        | GossipRequestType::Heartbeat(_)
        | GossipRequestType::PeerInfo(_)
        | GossipRequestType::Raft(_) => false,
    }
}

/// Whether or not a response should be ignored
fn should_ignore_response(resp: &GossipResponse) -> bool {
    // Ignore responses if the relayer is in bootstrap mode
    if !in_bootstrap_mode() {
        return false;
    }

    // We intentionally do not have a default case here so that when new response
    // types are added, we will remember to update this function
    match resp.body {
        GossipResponseType::Handshake(_) | GossipResponseType::OrderInfo(_) => true,
        GossipResponseType::Ack
        | GossipResponseType::Heartbeat(_)
        | GossipResponseType::PeerInfo(_)
        | GossipResponseType::Raft(_) => false,
    }
}

/// Whether or not we should ignore a pubsub message
fn should_ignore_pubsub(msg: &PubsubMessage) -> bool {
    // Ignore pubsub messages if the relayer is in bootstrap mode
    if !in_bootstrap_mode() {
        return false;
    }

    match msg {
        PubsubMessage::Orderbook(_) => true,
        PubsubMessage::Cluster(_) => false,
    }
}
