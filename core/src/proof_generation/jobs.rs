//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process

/// Represents a job enqueued in the proof manager's work queue
#[derive(Copy, Clone, Debug)]
pub enum ProofManagerJob {}
