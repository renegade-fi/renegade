//! Defines the main threading model of the proof generation module as a worker
//! that can be scheduled by the coordinator thread

use std::{
    sync::Arc,
    thread::{Builder, JoinHandle},
};

use common::{types::CancelChannel, worker::Worker};
use crossbeam::channel::Receiver;
use job_types::proof_manager::ProofManagerJob;
use rayon::ThreadPoolBuilder;

use super::{
    error::ProofManagerError,
    proof_manager::{ProofManager, PROOF_GENERATION_N_THREADS},
};

/// The name of the main worker thread
const MAIN_THREAD_NAME: &str = "proof-generation-main";

/// The configuration of the manager, used to hold work queues and tunables
#[derive(Clone, Debug)]
pub struct ProofManagerConfig {
    /// The job queue on which the manager may receive proof generation jobs
    pub job_queue: Receiver<ProofManagerJob>,
    /// The cancel channel that the coordinator uses to signal to the proof
    /// generation module that it should shut down
    pub cancel_channel: CancelChannel,
}

impl Worker for ProofManager {
    type WorkerConfig = ProofManagerConfig;
    type Error = ProofManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        // Build a thread pool for the worker
        let proof_generation_thread_pool = ThreadPoolBuilder::new()
            .num_threads(PROOF_GENERATION_N_THREADS)
            .build()
            .map_err(|err| ProofManagerError::Setup(err.to_string()))?;

        Ok(Self {
            job_queue: Some(config.job_queue),
            join_handle: None,
            thread_pool: Arc::new(proof_generation_thread_pool),
            cancel_channel: config.cancel_channel,
        })
    }

    fn name(&self) -> String {
        "proof-generation".to_string()
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Take ownership of the thread pool and job queue
        let job_queue = self.job_queue.take().unwrap();
        let thread_pool = self.thread_pool.clone();
        let cancel_channel = self.cancel_channel.clone();
        let handle = Builder::new()
            .name(MAIN_THREAD_NAME.to_string())
            .spawn(move || {
                Self::execution_loop(job_queue, thread_pool, cancel_channel)
                    .err()
                    .unwrap()
            })
            .map_err(|err| ProofManagerError::Setup(err.to_string()))?;

        self.join_handle = Some(handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.join_handle.take().unwrap()]
    }
}
