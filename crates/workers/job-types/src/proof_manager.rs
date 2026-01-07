//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process
//!
//! See the whitepaper https://renegade.fi/whitepaper.pdf for a formal specification
//! of the types defined here

use circuit_types::ProofLinkingHint;
use tokio::sync::oneshot::Sender;
use util::channels::{
    TracedCrossbeamReceiver, TracedCrossbeamSender, new_traced_crossbeam_channel,
};

/// The queue type for the proof manager
pub type ProofManagerQueue = TracedCrossbeamSender<ProofManagerJob>;
/// The receiver type for the proof manager
pub type ProofManagerReceiver = TracedCrossbeamReceiver<ProofManagerJob>;

/// Create a new proof manager queue and receiver
pub fn new_proof_manager_queue() -> (ProofManagerQueue, ProofManagerReceiver) {
    new_traced_crossbeam_channel()
}

// -------------
// | Job Types |
// -------------

/// TODO: Replace this with the real proof bundle
pub type ProofBundle = ();

/// Represents a job enqueued in the proof manager's work queue
#[derive(Debug)]
pub struct ProofManagerJob {
    /// The type of job being requested
    pub type_: ProofJob,
    /// The response channel to send the proof back along
    pub response_channel: Sender<ProofBundle>,
}

/// The job type and parameterization
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
pub enum ProofJob {
    // Dummy job
    Dummy,
}
