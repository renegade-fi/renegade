//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use crossbeam::channel::Receiver;

use super::jobs::ProofManagerJob;

/// The proof manager provides a messaging interface and implementation for proving statements
/// related to system state transitions
#[derive(Clone, Debug)]
pub struct ProofManager {
    /// The queue on which the proof manager receives new jobs
    /// TODO: Remove this lint allowance
    #[allow(dead_code)]
    pub(crate) job_queue: Receiver<ProofManagerJob>,
}
