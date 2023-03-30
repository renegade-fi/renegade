//! Defines a task that submits a transaction transferring an ERC20 token into
//! an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and re-indexing state

// TODO: Remove this
#![allow(unused)]

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use num_bigint::BigUint;
use serde::Serialize;

use crate::{
    proof_generation::jobs::{ProofManagerJob, ValidWalletUpdateBundle},
    starknet_client::client::StarknetClient,
    state::RelayerState,
};

use super::driver::{StateWrapper, Task};

/// The display name of the task
const DEPOSIT_BALANCE_TASK_NAME: &str = "deposit-balance";

/// Defines the long running flow for adding a balance to a wallet
pub struct DepositBalanceTask {
    /// The ERC20 address of the token to deposit
    pub mint: BigUint,
    /// The amount of the token to deposit
    pub amount: BigUint,
    /// The address to deposit from
    pub sender_address: BigUint,
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub state: DepositBalanceTaskState,
}

/// The error type for the deposit balance task
#[derive(Clone, Debug)]
pub enum DepositBalanceTaskError {
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the state of the deposit balance task
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DepositBalanceTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET UPDATE` from
    /// the proof management worker
    Proving,
    /// The task is submitting the transaction to the contract and awaiting
    /// transaction finality
    SubmittingTx {
        /// The proof of `VALID WALLET UPDATE` submitted to the contract
        proof_bundle: ValidWalletUpdateBundle,
    },
    /// The task has finished
    Completed,
}

impl Display for DepositBalanceTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::SubmittingTx { .. } => write!(f, "SubmittingTx"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl Serialize for DepositBalanceTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<DepositBalanceTaskState> for StateWrapper {
    fn from(state: DepositBalanceTaskState) -> Self {
        StateWrapper::DepositBalance(state)
    }
}

#[async_trait]
impl Task for DepositBalanceTask {
    type Error = DepositBalanceTaskError;
    type State = DepositBalanceTaskState;

    async fn step(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }

    fn completed(&self) -> bool {
        matches!(self.state(), Self::State::Completed)
    }

    fn state(&self) -> Self::State {
        self.state.clone()
    }

    fn name(&self) -> String {
        DEPOSIT_BALANCE_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl DepositBalanceTask {
    /// Constructor
    pub fn new(
        mint: BigUint,
        amount: BigUint,
        sender_address: BigUint,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            mint,
            amount,
            sender_address,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            state: DepositBalanceTaskState::Pending,
        }
    }
}
