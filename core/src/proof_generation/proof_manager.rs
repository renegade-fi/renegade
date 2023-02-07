//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use std::{sync::Arc, thread::JoinHandle};

use crossbeam::channel::Receiver;
use rayon::ThreadPool;

use super::{error::ProofManagerError, jobs::ProofManagerJob};

// -------------
// | Constants |
// -------------

/// The number of threads to allocate towards the proof generation worker pool
pub(crate) const PROOF_GENERATION_N_THREADS: usize = 2;

// --------------------
// | Proof Generation |
// --------------------

/// The proof manager provides a messaging interface and implementation for proving statements
/// related to system state transitions
#[derive(Debug)]
pub struct ProofManager {
    /// The queue on which the proof manager receives new jobs
    /// TODO: Remove this lint allowance
    #[allow(dead_code)]
    pub(crate) job_queue: Option<Receiver<ProofManagerJob>>,
    /// The handle of the main driver thread in the proof generation module
    pub(crate) join_handle: Option<JoinHandle<ProofManagerError>>,
    /// The threadpool of workers generating proofs for the system
    pub(crate) thread_pool: Arc<ThreadPool>,
}

impl ProofManager {
    /// The execution loop blocks on the job queue then schedules proof generation
    /// jobs onto a thread pool
    pub(crate) fn execution_loop(
        job_queue: Receiver<ProofManagerJob>,
        thread_pool: Arc<ThreadPool>,
    ) -> Result<(), ProofManagerError> {
        loop {
            // Dequeue the next job and hand it to the thread pool
            let job = job_queue
                .recv()
                .map_err(|err| ProofManagerError::JobQueueClosed(err.to_string()))?;
            thread_pool.install(move || {
                if let Err(e) = Self::handle_proof_job(job) {
                    println!("Error handling proof manager job: {}", e)
                }
            });
        }
    }

    /// The main job handler, run by a thread in the pool
    fn handle_proof_job(job: ProofManagerJob) -> Result<(), ProofManagerError> {
        println!("Handling job {:?}", job);
        Ok(())
    }
}
