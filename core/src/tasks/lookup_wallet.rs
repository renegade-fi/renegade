//! Defines a task that looks up a wallet in contract storage by its
//! public view key identifier, then begins managing the wallet

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use serde::Serialize;

use crate::{
    external_api::types::KeyChain, proof_generation::jobs::ProofManagerJob,
    starknet_client::client::StarknetClient, state::RelayerState,
};

use super::driver::{StateWrapper, Task};

/// The task name for the lookup wallet task
const LOOKUP_WALLET_TASK_NAME: &str = "lookup-wallet";

/// Represents a task to lookup a wallet in contract storage
pub struct LookupWalletTask {
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
    /// A starknet client for the task to submit transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task's execution
    pub task_state: LookupWalletTaskState,
}

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize)]
pub enum LookupWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl Display for LookupWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<LookupWalletTaskState> for StateWrapper {
    fn from(state: LookupWalletTaskState) -> Self {
        StateWrapper::LookupWallet(state)
    }
}

/// The error type thrown by the wallet lookup task
#[derive(Clone, Debug)]
pub enum LookupWalletTaskError {
    /// Error interacting with the starknet client
    Starknet(String),
}

impl Display for LookupWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

#[async_trait]
impl Task for LookupWalletTask {
    type State = LookupWalletTaskState;
    type Error = LookupWalletTaskError;

    fn completed(&self) -> bool {
        matches!(self.state(), LookupWalletTaskState::Completed)
    }

    fn name(&self) -> String {
        LOOKUP_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            LookupWalletTaskState::Pending => {
                self.task_state = LookupWalletTaskState::FindingWallet
            }
            LookupWalletTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = LookupWalletTaskState::CreatingValidityProofs;
            }
            LookupWalletTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = LookupWalletTaskState::Completed;
            }
            LookupWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            }
        }

        Ok(())
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl LookupWalletTask {
    /// Constructor
    pub fn new(
        key_chain: KeyChain,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            key_chain,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: LookupWalletTaskState::Pending,
        }
    }

    /// Find the wallet in the contract storage and create an opening for the wallet
    async fn find_wallet(&mut self) -> Result<(), LookupWalletTaskError> {
        unimplemented!("")
    }

    /// Prove `VALID COMMITMENTS` for all orders in the wallet
    async fn create_validity_proofs(&self) -> Result<(), LookupWalletTaskError> {
        unimplemented!("")
    }
}
