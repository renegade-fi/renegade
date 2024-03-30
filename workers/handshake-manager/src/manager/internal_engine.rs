//! Defines logic for running the internal matching engine on a given order

use circuit_types::{fixed_point::FixedPoint, order::Order};
use common::types::{
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    tasks::{SettleMatchInternalTaskDescriptor, TaskDescriptor, TaskIdentifier},
    wallet::{OrderIdentifier, Wallet, WalletIdentifier},
};
use job_types::task_driver::TaskDriverJob;
use rand::{seq::SliceRandom, thread_rng};
use tracing::{error, info};
use util::{err_str, matching_engine::match_orders, res_some};

use crate::{
    error::HandshakeManagerError,
    manager::handshake::{ERR_NO_ORDER, ERR_NO_PRICE_DATA, ERR_NO_WALLET},
};

use super::HandshakeExecutor;

/// Error emitted when proofs of validity cannot be found for an order
const ERR_MISSING_PROOFS: &str = "validity proofs not found in global state";

// ------------------------
// | Matching Engine Impl |
// ------------------------

impl HandshakeExecutor {
    /// Run the internal matching engine on the given order
    ///
    /// TODO: This could be optimized by indexing orders by asset pairs in the
    /// global state, but this would require further denormalizing the order
    /// book index. We will hold off on this optimization until we either:
    ///     1. Determine this code path to be a bottleneck
    ///     2. Have a better state management abstraction that makes
    ///        denormalization easier
    pub async fn run_internal_matching_engine(
        &self,
        order: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        info!("Running internal matching engine on order {order}");
        let mut rng = thread_rng();

        // Lookup the order and its wallet
        let (network_order, wallet) = self.fetch_order_and_wallet(&order)?;
        let my_order = wallet
            .orders
            .get(&network_order.id)
            .ok_or_else(|| HandshakeManagerError::State(ERR_NO_ORDER.to_string()))?;
        let (my_proof, my_witness) = self
            .get_validity_proof_and_witness(&network_order.id)?
            .ok_or_else(|| HandshakeManagerError::State(ERR_MISSING_PROOFS.to_string()))?;

        // Sample a price to match the order at
        let price = self.get_execution_price(&network_order.id).await?;

        // Fetch all other orders that are ready for matches
        // Shuffle the ordering of the other orders for fairness
        let mut other_orders = self.global_state.get_locally_matchable_orders()?;
        other_orders.shuffle(&mut rng);

        // Match against each other order in the local book
        for order_id in other_orders {
            // Same order
            if network_order.id == order_id {
                continue;
            }

            // Same wallet
            let other_wallet_id = self
                .global_state
                .get_wallet_for_order(&order_id)?
                .ok_or_else(|| HandshakeManagerError::State(ERR_NO_WALLET.to_string()))?;
            if other_wallet_id == wallet.wallet_id {
                continue;
            }

            // Lookup the witness used for this order
            let (other_proof, other_witness) =
                match self.get_validity_proof_and_witness(&order_id)? {
                    Some(proof) => proof,
                    None => continue,
                };

            // Lookup the other order and match on it
            let order2 = match self.global_state.get_managed_order(&order_id)? {
                Some(order) => order,
                None => continue,
            };

            // If a match is successful, break from the loop, the settlement task will
            // re-enqueue a job for the internal engine to run again
            match self
                .try_match_and_settle(
                    my_order.clone(),
                    order2,
                    wallet.wallet_id,
                    other_wallet_id,
                    price,
                    my_witness.clone(),
                    other_witness.clone(),
                    my_proof.clone(),
                    other_proof.clone(),
                )
                .await
            {
                Ok(did_match) => {
                    // Stop matching if a match was found
                    if did_match {
                        return Ok(());
                    }
                },
                Err(e) => error!(
                    "internal match settlement failed for {} x {}: {e}",
                    network_order.id, order_id,
                ),
            }
        }

        info!("No internal matches found for {order:?}");
        Ok(())
    }

    /// Try a match and settle it if the two orders cross
    #[allow(clippy::too_many_arguments)]
    async fn try_match_and_settle(
        &self,
        o1: Order,
        o2: Order,
        wallet_id1: WalletIdentifier,
        wallet_id2: WalletIdentifier,
        price: FixedPoint,
        validity_witness1: OrderValidityWitnessBundle,
        validity_witness2: OrderValidityWitnessBundle,
        validity_proof1: OrderValidityProofBundle,
        validity_proof2: OrderValidityProofBundle,
    ) -> Result<bool, HandshakeManagerError> {
        // Match the orders
        let b1 = &validity_witness1.commitment_witness.balance_send;
        let b2 = &validity_witness2.commitment_witness.balance_send;
        let match_result = match match_orders(&o1, &o2, b1, b2, price) {
            Some(match_) => match_,
            None => return Ok(false),
        };

        // Submit the match to the task driver
        let task: TaskDescriptor = SettleMatchInternalTaskDescriptor::new(
            price,
            wallet_id1,
            wallet_id2,
            validity_proof1,
            validity_witness1,
            validity_proof2,
            validity_witness2,
            match_result,
        )
        .unwrap()
        .into();

        let wallet_ids = vec![wallet_id1, wallet_id2];

        let task_id = TaskIdentifier::new_v4();
        let job = TaskDriverJob::RunImmediate { task_id, wallet_ids, task };
        self.task_queue.send(job).map_err(err_str!(HandshakeManagerError::TaskError))?;

        // Await settlement, returning true to indicate a match was successfully
        // processed
        self.await_settlement_task(task_id).await.map(|_| true)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Fetch the execution price for an order
    async fn get_execution_price(
        &self,
        order: &OrderIdentifier,
    ) -> Result<FixedPoint, HandshakeManagerError> {
        let (base, quote) = self.token_pair_for_order(order)?;
        let price = self
            .fetch_price_vector()
            .await?
            .find_pair(&base, &quote)
            .ok_or_else(|| HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string()))?
            .2; // (base, quote, price)

        Ok(FixedPoint::from_f64_round_down(price))
    }

    /// Get the validity proof and witness for a given order
    fn get_validity_proof_and_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<(OrderValidityProofBundle, OrderValidityWitnessBundle)>, HandshakeManagerError>
    {
        let state = &self.global_state;
        let proof = res_some!(state.get_validity_proofs(order_id)?);
        let witness = res_some!(state.get_validity_proof_witness(order_id)?);

        Ok(Some((proof, witness)))
    }

    /// Fetch the order and wallet for the given order identifier
    fn fetch_order_and_wallet(
        &self,
        order: &OrderIdentifier,
    ) -> Result<(NetworkOrder, Wallet), HandshakeManagerError> {
        let state = &self.global_state;
        let order = state
            .get_order(order)?
            .ok_or_else(|| HandshakeManagerError::State(ERR_NO_ORDER.to_string()))?;

        let wallet = match state.get_wallet_for_order(&order.id)? {
            Some(wallet) => state.get_wallet(&wallet)?,
            None => None,
        }
        .ok_or_else(|| HandshakeManagerError::State(ERR_NO_WALLET.to_string()))?;

        Ok((order, wallet))
    }
}
