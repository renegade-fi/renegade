pub(crate) mod types;

use crossbeam::channel::Receiver;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    sync::Arc,
    thread::{self, JoinHandle}, time::Duration
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    gossip::{types::WrappedPeerId, 
        api::{
            GossipOutbound, GossipRequest, 
            HandshakeMessage, HandshakeOperation, GossipResponse
        }
    },
    state::GlobalRelayerState, 
};

use self::types::HandshakeExecutionJob;

/**
 * Groups logic for handshakes executed through a threadpool at period intervals
 */

// The number of threads executing handshakes
const NUM_HANDSHAKE_THREADS: usize = 8;

// The interval at which to initiate handshakes
const HANDSHAKE_INTERVAL_MS: u64 = 5000;

const NANOS_PER_MILLI: u64 = 1_000_000;

pub struct HandshakeManager {
    timer: HandshakeTimer,
    relay: HandshakeJobRelay,
}

impl HandshakeManager {
    pub fn new(
        global_state: GlobalRelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
        job_receiver: Receiver<HandshakeExecutionJob>
    ) -> Self {
        // Build a thread pool to handle handshake operations
        println!("Starting execution loop for handshake protocol executor...");

        let thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(NUM_HANDSHAKE_THREADS)
                .build()
                .unwrap()
        );

        // Start a timer thread
        let timer = HandshakeTimer::new(thread_pool.clone(), global_state, network_channel.clone());
        let relay = HandshakeJobRelay::new(
            thread_pool.clone(), job_receiver, network_channel
        );

        HandshakeManager { timer, relay } 
    }

    // Joins execution of the calling thread to the HandshakeManager's execution
    pub fn join(self) -> thread::Result<()> {
        self.timer.join();
        self.relay.join()
    }

    // Perform a handshake, dummy job for now
    pub fn perform_handshake(
        peer_id: WrappedPeerId, 
        network_channel: UnboundedSender<GossipOutbound>
    ) {
        // Send a handshake message to the given peer_id
        network_channel.send(
            GossipOutbound::Request { 
                peer_id, 
                message: GossipRequest::Handshake(
                    HandshakeMessage { operation: HandshakeOperation::MPC }
                )
            }
        );
    }

    pub fn respond_handshake(
        job: HandshakeExecutionJob,
        network_channel: UnboundedSender<GossipOutbound>
    ) {
        match job {
            HandshakeExecutionJob::ProcessHandshakeRequest { 
                response_channel, ..
            } => {
                network_channel.send(GossipOutbound::Response { 
                    channel: response_channel, 
                    message: GossipResponse::Handshake()
                });
            }
        }
    }

}

/**
 * Implements a timer that periodically enqueues jobs to the threadpool
 */
struct HandshakeTimer {
    thread_handle: thread::JoinHandle<()>
}

impl HandshakeTimer {
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        global_state: GlobalRelayerState,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Self {
        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        // Spawn the execution loop
        let thread_handle = thread::Builder::new()
            .name("handshake-manager-timer".to_string())
            .spawn(move || {
                Self::execution_loop(refresh_interval, thread_pool, global_state, network_channel)
            })
            .unwrap();

        HandshakeTimer { thread_handle }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_handle.join()
    }

    // The execution loop of the timer, periodically enqueues handshake jobs
    fn execution_loop(
        refresh_interval: Duration,
        thread_pool: Arc<ThreadPool>,
        global_state: GlobalRelayerState,
        network_channel: UnboundedSender<GossipOutbound>
    ) {
        // Get local peer ID, skip handshaking with self
        let local_peer_id: WrappedPeerId;
        {
            let locked_state = global_state.read().expect("global state lock poisoned");
            local_peer_id = locked_state.local_peer_id.expect("local PeerID not assigned"); 
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
                        HandshakeManager::perform_handshake(
                            peer_info.get_peer_id(), sender_copy
                        );
                    })
                }
            } // locked_state released here

            thread::sleep(refresh_interval);
        } 
    }
}


/**
 * Implements a listener that relays from a crossbeam channel to the handshake threadpool
 * Used as a layer of indirection to provide a consistent interface at the network level
 */
struct HandshakeJobRelay {
    thread_handle: JoinHandle<()>
}

impl HandshakeJobRelay {
    pub fn new(
        thread_pool: Arc<ThreadPool>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) -> Self {
        let thread_handle = thread::Builder::new()
            .name("handshake-job-relay".to_string())
            .spawn(move || { Self::execution_loop(thread_pool, job_channel, network_channel) })
            .unwrap();
        
        HandshakeJobRelay { thread_handle }
    }

    // Joins execution of the calling thread to the execution loop
    pub fn join(self) -> thread::Result<()> {
        self.thread_handle.join()
    }

    fn execution_loop(
        thread_pool: Arc<ThreadPool>,
        job_channel: Receiver<HandshakeExecutionJob>,
        network_channel: UnboundedSender<GossipOutbound>,
    ) {
        loop {
            // Wait for the next message and forward to the thread pool
            let job = job_channel.recv().unwrap();    
            let channel_copy = network_channel.clone();
            thread_pool.install(move || {
                HandshakeManager::respond_handshake(job, channel_copy)
            })
        }
    }
}