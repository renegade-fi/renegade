//! Handles the flow of adding a new order to a wallet

use std::fmt::Display;

use circuits::types::order::Order as CircuitOrder;
use crossbeam::channel::Sender as CrossbeamSender;
use tracing::log;

use crate::{
    external_api::types::Order,
    proof_generation::jobs::ProofManagerJob,
    starknet_client::client::StarknetClient,
    state::{wallet::WalletIdentifier, RelayerState},
};

/// The error type for the task
#[derive(Clone, Debug)]
pub enum NewOrderTaskError {}

impl Display for NewOrderTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The task definition for the long-run async flow of creating
/// a new order within a wallet
pub struct NewOrderTask {
    /// The ID of the wallet to create the order within
    wallet_id: WalletIdentifier,
    /// The order to add to the wallet
    order: CircuitOrder,
    /// A starknet client for the task to submit transactions
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// The work queue for the proof manager
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl NewOrderTask {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        order: Order,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        // Cast explicitly to an order type that is indexed in the state
        let order: CircuitOrder = order.into();

        Self {
            wallet_id,
            order,
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }

    /// Run the task to completion
    pub async fn run(self) -> Result<(), NewOrderTaskError> {
        log::info!("got to create new order task");
        Ok(())
    }
}
