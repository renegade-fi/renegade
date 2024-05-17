//! Return types from applicator methods
//!
//! We provide "function call" like semantics over the consensus engine by
//! allowing the applicator to return a value from the engine to its callers.
//! In this case the callers are locations awaiting a proposal's application
//!
//! Each of such waiters will be given a copy of the return value

use common::types::mpc_preprocessing::PairwiseOfflineSetup;

use super::error::StateApplicatorError;

/// The return type from the Applicator
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplicatorReturnType {
    /// A set of MPC preprocessing values that are ready to be used
    MpcPrep(PairwiseOfflineSetup),
    /// No return value
    None,
    /// The application of the proposal failed in an expected manner
    Rejected(StateApplicatorError),
}

// Downcasting conversions

impl From<ApplicatorReturnType> for PairwiseOfflineSetup {
    fn from(return_type: ApplicatorReturnType) -> Self {
        match return_type {
            ApplicatorReturnType::MpcPrep(setup) => setup,
            _ => panic!("Expected MpcPrep, got: {return_type:?}"),
        }
    }
}
