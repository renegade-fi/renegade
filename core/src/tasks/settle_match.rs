//! Groups the task definition for settling a match after an MPC has taken place
//! Broadly this breaks down into the following steps:
//!     - Build the notes that result from the match and encrypt them
//!     - Submit these notes and the relevant proofs to the contract in a `match` transaction
//!     - Await transaction finality, then lookup the notes in the commitment tree
//!     - Build a settlement proof, and submit this to the contract in a `settle` transaction
//!     - Await finality then update the wallets into the relayer-global state

// TODO: Remove this
#![allow(unused)]

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use serde::Serialize;

use crate::{
    proof_generation::jobs::{ProofManagerJob, ValidMatchEncryptBundle},
    starknet_client::client::StarknetClient,
    state::RelayerState,
};

use super::driver::{StateWrapper, Task};

/// The displayable name for the settle match task
const SETTLE_MATCH_TASK_NAME: &str = "settle-match";

// -------------------
// | Task Definition |
// -------------------

/// Describes the settle task
pub struct SettleMatchTask {
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub task_state: SettleMatchTaskState,
}

/// The state of the settle match task
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum SettleMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving `VALID MATCH ENCRYPTION`
    ProvingEncryption,
    /// The task is submitting the match transaction
    SubmittingMatch {
        /// The proof of `VALID MATCH ENCRYPTION`
        proof: ValidMatchEncryptBundle,
    },
    /// The task is proving `VALID SETTLE`
    ProvingSettle,
    /// The task is submitting the settle transaction
    SubmittingSettle {
        /// The proof of `VALID SETTLE`
        proof: (),
    },
    /// The task is updating order proofs after the settled walled is confirmed
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl From<SettleMatchTaskState> for StateWrapper {
    fn from(state: SettleMatchTaskState) -> Self {
        StateWrapper::SettleMatch(state)
    }
}

/// Display implementation that removes variant fields
impl Display for SettleMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleMatchTaskState::SubmittingMatch { .. } => write!(f, "SubmittingMatch"),
            SettleMatchTaskState::SubmittingSettle { .. } => write!(f, "SubmittingSettle"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// The error type that this task emits
#[derive(Clone, Debug, Serialize)]
pub enum SettleMatchTaskError {}

impl Display for SettleMatchTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current task state
        match self.state() {
            SettleMatchTaskState::Pending => {
                self.task_state = SettleMatchTaskState::ProvingEncryption
            }

            SettleMatchTaskState::ProvingEncryption => {
                let proof = self.prove_encryption()?;
                self.task_state = SettleMatchTaskState::SubmittingMatch { proof };
            }

            SettleMatchTaskState::SubmittingMatch { proof } => {
                self.submit_match(proof)?;
                self.task_state = SettleMatchTaskState::ProvingSettle;
            }

            SettleMatchTaskState::ProvingSettle => {
                let proof = self.prove_settle()?;
                self.task_state = SettleMatchTaskState::SubmittingSettle { proof };
            }

            SettleMatchTaskState::SubmittingSettle { proof } => {
                self.submit_settle(proof)?;
                self.task_state = SettleMatchTaskState::UpdatingValidityProofs;
            }

            SettleMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs()?;
                self.task_state = SettleMatchTaskState::Completed;
            }

            SettleMatchTaskState::Completed => {
                unreachable!("step called on completed task")
            }
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_MATCH_TASK_NAME.to_string()
    }

    fn completed(&self) -> bool {
        matches!(self.state(), SettleMatchTaskState::Completed)
    }

    fn state(&self) -> SettleMatchTaskState {
        self.task_state.clone()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleMatchTask {
    /// Constructor
    pub fn new() -> Self {
        unimplemented!("")
    }

    /// Prove `VALID MATCH ENCRYPTION` on the match
    fn prove_encryption(&self) -> Result<ValidMatchEncryptBundle, SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Submit the match transaction to the contract
    fn submit_match(&self, proof: ValidMatchEncryptBundle) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Prove `VALID SETTLE` on the transaction
    fn prove_settle(&self) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Submit the settle transaction to the contract
    fn submit_settle(&self, proof: ()) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }
}
