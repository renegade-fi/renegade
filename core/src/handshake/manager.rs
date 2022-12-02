//! The handshake module handles the execution of handshakes from negotiating
//! a pair of orders to match, all the way through settling any resulting match

use crossbeam::channel::Receiver;
use rayon::ThreadPool;
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::{
        gossip::{GossipOutbound, GossipRequest, GossipResponse},
        handshake::{HandshakeMessage, HandshakeOperation},
    },
    gossip::types::WrappedPeerId,
    state::GlobalRelayerState,
    CancelChannel,
};

use super::{error::HandshakeManagerError, jobs::HandshakeExecutionJob};

/// The interval at which to initiate handshakes
const HANDSHAKE_INTERVAL_MS: u64 = 5000;
/// Number of nanoseconds in a millisecond, for convenienc
const NANOS_PER_MILLI: u64 = 1_000_000;

/// Manages requests to handshake from a peer and sends outbound requests to initiate
/// a handshake
pub struct HandshakeManager {
    /// The hanshake timer; periodically enqueues outbound handshake requests
    pub(super) timer: HandshakeTimer,
    /// The job realay; provides a shim between the network interface and the manager
    pub(super) relay: HandshakeJobRelay,
}

impl HandshakeManager {
    /// Perform a handshake, dummy job for now
    pub fn perform_handshake(
        peer_id: WrappedPeerId,
        network_channel: UnboundedSender<GossipOutbound>,
    ) {
        // Send a handshake message to the given peer_id
        // Panic if channel closed, no way to recover
        network_channel
            .send(GossipOutbound::Request {
                peer_id,
                message: GossipRequest::Handshake(HandshakeMessage {
                    operation: HandshakeOperation::Mpc,
                }),
            })
            .unwrap();
    }

    /// Respond to a handshake request from a peer
    pub fn respond_handshake(
        job: HandshakeExecutionJob,
        network_channel: UnboundedSender<GossipOutbound>,
    ) {
        match job {
            HandshakeExecutionJob::ProcessHandshakeRequest {
                response_channel, ..
            } => {
                // Send the message and unwrap the result; the only error type possible
                // is that the channel is closed, so panic the thread in that case
                network_channel
                    .send(GossipOutbound::Response {
                        channel: response_channel,
                        message: GossipResponse::Handshake(),
                    })
                    .unwrap();
            }
        }
    }
}

/// Implements a timer that periodically enqueues jobs to the threadpool that
/// tell the manager to send outbound handshake requests
pub(super) struct HandshakeTimer {
    /// The join handle of the thread executing timer interrupts
    thread_handle: Option<thread::JoinHandle<HandshakeManagerError>>,
}

impl HandshakeTimer {
    /// Construct a new timer
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        global_state: GlobalRelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Spawn the execution loop
        let thread_handle = thread::Builder::new()
            .name("handshake-manager-timer".to_string())
            .spawn(move || {
                Self::execution_loop(
                    refresh_interval,
                    thread_pool,
                    global_state,
                    network_channel,
                    cancel,
                )
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        Ok(HandshakeTimer {
            thread_handle: Some(thread_handle),
        })
    }

    /// Consume the join handle for the executor thread, this leaves no join handle in
    /// its place, meaning this can only be called once
    pub fn join_handle(&mut self) -> JoinHandle<HandshakeManagerError> {
        self.thread_handle.take().unwrap()
    }

    /// The execution loop of the timer, periodically enqueues handshake jobs
    fn execution_loop(
        refresh_interval: Duration,
        thread_pool: Arc<ThreadPool>,
        global_state: GlobalRelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> HandshakeManagerError {
        // Get local peer ID, skip handshaking with self
        let local_peer_id: WrappedPeerId;
        {
            let locked_state = global_state.read().expect("global state lock poisoned");
            local_peer_id = locked_state
                .local_peer_id
                .expect("local PeerID not assigned");
        } // locked_state released here

        // Enqueue refreshes periodically
        loop {
            {
                let locked_state = global_state.read().expect("global state lock poisoned");
                for (_, peer_info) in locked_state.known_peers.iter() {
                    // Skip handshaking with self
                    if peer_info.get_peer_id() == local_peer_id {
                        continue;
                    }

                    let sender_copy = network_channel.clone();

                    thread_pool.install(move || {
                        HandshakeManager::perform_handshake(peer_info.get_peer_id(), sender_copy);
                    })
                }
            } // locked_state released here

            // Check for a cancel signal before sleeping and after
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            thread::sleep(refresh_interval);
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }
        }
    }
}

/// Implements a listener that relays from a crossbeam channel to the handshake threadpool
/// Used as a layer of indirection to provide a consistent interface at the network level
pub(super) struct HandshakeJobRelay {
    /// The join handle of the thread executing the handshake relay
    thread_handle: Option<JoinHandle<HandshakeManagerError>>,
}

impl HandshakeJobRelay {
    /// Create a new job relay
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> Result<Self, HandshakeManagerError> {
        let thread_handle = thread::Builder::new()
            .name("handshake-job-relay".to_string())
            .spawn(move || Self::execution_loop(thread_pool, job_channel, network_channel, cancel))
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;

        Ok(HandshakeJobRelay {
            thread_handle: Some(thread_handle),
        })
    }

    /// Consumes the join handle that the executor operates on, leaving `None` in its
    /// place. This means that this method may only be called once
    pub fn join_handle(&mut self) -> JoinHandle<HandshakeManagerError> {
        self.thread_handle.take().unwrap()
    }

    /// The main execution loop, listens on the channel and forwards jobs to the handshake manager
    fn execution_loop(
        thread_pool: Arc<ThreadPool>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
        cancel: CancelChannel,
    ) -> HandshakeManagerError {
        loop {
            // Check if the coordinator has cancelled the handshake manager
            if !cancel.is_empty() {
                return HandshakeManagerError::Cancelled("received cancel signal".to_string());
            }

            // Wait for the next message and forward to the thread pool
            let job = job_channel.recv().unwrap();
            let channel_copy = network_channel.clone();
            thread_pool.install(move || HandshakeManager::respond_handshake(job, channel_copy))
        }
    }
}
