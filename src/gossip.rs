pub(crate) mod api;
mod composed_protocol;
mod heartbeat_protocol;
mod errors;
pub(crate) mod network_manager;
pub(crate) mod types;

// This file groups logic for the package-public gossip interface
use crossbeam::channel::{Sender, Receiver};
use std::{
    error::Error,
};
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::{
    gossip::{
        heartbeat_protocol::{
            HeartbeatProtocolExecutor
        },
    },
    state::GlobalRelayerState,
};

use self::{heartbeat_protocol::HeartbeatExecutorJob, api::GossipOutbound, types::WrappedPeerId};

pub struct GossipServer {
    // Executors
    heartbeat_executor: heartbeat_protocol::HeartbeatProtocolExecutor,
}

impl GossipServer {
    // Creates a new gossip server
    pub async fn new(
        local_peer_id: WrappedPeerId,
        global_state: GlobalRelayerState,
        heartbeat_worker_sender: Sender<HeartbeatExecutorJob>,
        heartbeat_worker_receiver: Receiver<HeartbeatExecutorJob>,
        network_sender: TokioSender<GossipOutbound>
    ) -> Result<Self, Box<dyn Error>> {
        // Register self as replicator of owned wallets using peer info from network manager
        {
            let global_copy = global_state.clone();
            let mut locked_global_state = global_copy.write().expect("global state lock poisoned");

            for (_, wallet) in locked_global_state.managed_wallets.iter_mut() {
                wallet.metadata.replicas.push(local_peer_id);
            }
        } // locked_global_state released

        // Heartbeat protocol executor; handles sending and receiving heartbeats
        let heartbeat_executor = HeartbeatProtocolExecutor::new(
            local_peer_id,
            network_sender,
            heartbeat_worker_sender.clone(),
            heartbeat_worker_receiver,
            global_state.clone()
        );

        Ok(Self { 
            heartbeat_executor,
        })
    }

    // Joins execution of calling thread to the execution of the GossipServer's
    // various workers
    pub fn join(self) {
        self.heartbeat_executor.join();
    }
}