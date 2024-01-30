//! Timers which control the heartbeat interval

use std::{thread, time::Duration};

use job_types::gossip_server::GossipServerJob;
use state::State;
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::errors::GossipError;

/// HeartbeatTimer handles the process of enqueuing jobs to perform
/// a heartbeat on regular intervals
#[derive(Debug)]
pub(super) struct HeartbeatTimer;

impl HeartbeatTimer {
    /// Spawns two timers, one for sending intra-cluster heartbeat messages,
    /// another for inter-cluster The interval parameters specify how often
    /// the timers should cycle through all peers in their target list
    pub fn new(
        job_queue: TokioSender<GossipServerJob>,
        intra_cluster_interval_ms: u64,
        inter_cluster_interval_ms: u64,
        global_state: State,
    ) -> Self {
        // Narrowing cast is okay, precision is not important here
        let intra_cluster_wait_period = Duration::from_millis(intra_cluster_interval_ms);
        let inter_cluster_wait_period = Duration::from_millis(inter_cluster_interval_ms);

        // Begin the timing loops
        let job_queue_clone = job_queue.clone();
        let global_state_clone = global_state.clone();
        thread::Builder::new()
            .name("intra-cluster-heartbeat-timer".to_string())
            .spawn(move || {
                Self::execution_loop(
                    true, // intra_cluster
                    job_queue_clone,
                    intra_cluster_wait_period,
                    global_state_clone,
                )
            })
            .unwrap();

        thread::Builder::new()
            .name("non-cluster-heartbeat-timer".to_string())
            .spawn(move || {
                Self::execution_loop(
                    false, // intra_cluster
                    job_queue,
                    inter_cluster_wait_period,
                    global_state,
                )
            })
            .unwrap();

        Self {}
    }

    /// Main timing loop for heartbeats sent to nodes
    ///
    /// The `intra_cluster` flag determines whether this is the intra-cluster
    /// loop or inter-cluster. We heartbeat cluster peers more frequently than
    /// non-cluster peers, so they require different timing loops
    ///
    /// We space out the heartbeat requests to give a better traffic pattern.
    /// This means that in each time quantum, one heartbeat is scheduled. We
    /// compute the length of a time quantum with respect to the heartbeat
    /// period constant defined above. That is, we specify the interval in
    /// between heartbeats for a given peer, and space out all heartbeats in
    /// that interval
    fn execution_loop(
        intra_cluster: bool,
        job_queue: TokioSender<GossipServerJob>,
        wait_period: Duration,
        global_state: State,
    ) -> Result<(), GossipError> {
        let local_peer_id = global_state.get_peer_id()?;
        let cluster_id = global_state.get_cluster_id()?;

        loop {
            // Get all peers in the local peer's cluster
            let peers = if intra_cluster {
                global_state.get_cluster_peers(&cluster_id)?
            } else {
                global_state.get_non_cluster_peers(&cluster_id)?
            };

            let wait_time = wait_period / (peers.len() as u32);
            for peer in peers.into_iter().filter(|peer| peer != &local_peer_id) {
                if let Err(err) = job_queue.send(GossipServerJob::ExecuteHeartbeat(peer)) {
                    return Err(GossipError::TimerFailed(err.to_string()));
                }

                thread::sleep(wait_time);
            }
        }
    }
}
