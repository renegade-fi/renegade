//! Defines the main threading model of the proof generation module as a worker
//! that can be scheduled by the coordinator thread

use crossbeam::channel::Receiver;

use crate::worker::Worker;

use super::{error::ProofManagerError, jobs::ProofManagerJob, proof_manager::ProofManager};

/// The configuration of the manager, used to hold work queues and tunables
#[derive(Clone, Debug)]
pub struct ProofManagerConfig {
    /// The job queue on which the manager may receive proof generation jobs
    pub job_queue: Receiver<ProofManagerJob>,
}

impl Worker for ProofManager {
    type WorkerConfig = ProofManagerConfig;
    type Error = ProofManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            job_queue: config.job_queue,
        })
    }

    fn name(&self) -> String {
        "proof-manager-main".to_string()
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }

    fn join(&mut self) -> Vec<std::thread::JoinHandle<Self::Error>> {
        unimplemented!("")
    }
}
