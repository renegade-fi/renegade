//! Pay a relayer fee for a balance

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::Amount;
use common::types::proof_bundles::RelayerFeeSettlementBundle;
use common::types::tasks::PayRelayerFeeTaskDescriptor;
use common::types::wallet::Wallet;
use job_types::network_manager::NetworkManagerQueue;
use job_types::proof_manager::ProofManagerQueue;
use num_bigint::BigUint;
use serde::Serialize;
use state::error::StateError;
use state::State;
use tracing::instrument;

use crate::driver::StateWrapper;
use crate::traits::{Task, TaskContext, TaskError, TaskState};

/// The name of the task
const TASK_NAME: &str = "pay-relayer-fee";

/// The error message emitted when the wallet is not found
const WALLET_NOT_FOUND: &str = "wallet not found";
/// The error message emitted when the balance is missing
const ERR_BALANCE_MISSING: &str = "balance missing";

// --------------
// | Task State |
// --------------

/// Defines the state of the relayer fee payment task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum PayRelayerFeeTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving fee payment for the balance
    ProvingPayment,
    /// The task is submitting a fee payment transaction
    SubmittingPayment,
    /// The task is finding the new Merkle opening for the wallet
    FindingOpening,
    /// The task is updating validity proofs for the wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for PayRelayerFeeTaskState {
    fn commit_point() -> Self {
        PayRelayerFeeTaskState::SubmittingPayment
    }

    fn completed(&self) -> bool {
        matches!(self, PayRelayerFeeTaskState::Completed)
    }
}

impl Display for PayRelayerFeeTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<PayRelayerFeeTaskState> for StateWrapper {
    fn from(value: PayRelayerFeeTaskState) -> Self {
        StateWrapper::PayRelayerFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the pay fees task
#[derive(Clone, Debug)]
pub enum PayRelayerFeeTaskError {
    /// An error interacting with Arbitrum
    Arbitrum(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for PayRelayerFeeTaskError {
    fn retryable(&self) -> bool {
        match self {
            PayRelayerFeeTaskError::Arbitrum(_)
            | PayRelayerFeeTaskError::ProofGeneration(_)
            | PayRelayerFeeTaskError::State(_)
            | PayRelayerFeeTaskError::UpdateValidityProofs(_) => true,
        }
    }
}

impl Display for PayRelayerFeeTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for PayRelayerFeeTaskError {}

impl From<StateError> for PayRelayerFeeTaskError {
    fn from(err: StateError) -> Self {
        PayRelayerFeeTaskError::State(err.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the pay fees task
pub struct PayRelayerFeeTask {
    /// The balance to pay fees for
    pub mint: BigUint,
    /// The wallet that this task pays fees for
    pub old_wallet: Wallet,
    /// The new wallet after fees have been paid
    pub new_wallet: Wallet,
    /// The proof of `VALID RELAYER FEE SETTLEMENT` used to pay the protocol fee
    pub protocol_proof: Option<RelayerFeeSettlementBundle>,
    /// The arbitrum client used for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A hand to the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's queue
    pub network_sender: NetworkManagerQueue,
    /// The current state of the task
    pub task_state: PayRelayerFeeTaskState,
}

#[async_trait]
impl Task for PayRelayerFeeTask {
    type State = PayRelayerFeeTaskState;
    type Error = PayRelayerFeeTaskError;
    type Descriptor = PayRelayerFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let old_wallet = ctx
            .state
            .get_wallet(&descriptor.wallet_id)?
            .ok_or_else(|| PayRelayerFeeTaskError::State(WALLET_NOT_FOUND.to_string()))?;
        let new_wallet = Self::get_new_wallet(&descriptor.balance_mint, &old_wallet)?;

        Ok(Self {
            mint: descriptor.balance_mint,
            old_wallet,
            new_wallet,
            protocol_proof: None,
            arbitrum_client: ctx.arbitrum_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: PayRelayerFeeTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        todo!()
    }

    fn completed(&self) -> bool {
        self.task_state.completed()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl PayRelayerFeeTask {
    // -----------
    // | Helpers |
    // -----------

    /// Clone the old wallet and update it to reflect the fee payment
    fn get_new_wallet(
        mint: &BigUint,
        old_wallet: &Wallet,
    ) -> Result<Wallet, PayRelayerFeeTaskError> {
        let mut new_wallet = old_wallet.clone();
        let balance = new_wallet
            .get_balance_mut(mint)
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_BALANCE_MISSING.to_string()))?;

        balance.relayer_fee_balance = Amount::from(0u8);
        new_wallet.reblind_wallet();

        Ok(new_wallet)
    }
}
