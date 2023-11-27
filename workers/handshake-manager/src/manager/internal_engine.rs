//! Defines logic for running the internal matching engine on a given order

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::MatchResult,
    traits::LinkableType,
};
use common::types::{
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::{OrderIdentifier, Wallet},
};
use itertools::Itertools;
use mpc_stark::algebra::scalar::Scalar;
use rand::{seq::SliceRandom, thread_rng};
use renegade_crypto::fields::scalar_to_u64;
use task_driver::settle_match_internal::SettleMatchInternalTask;
use tracing::log;
use util::matching_engine::match_orders;

use crate::{
    error::HandshakeManagerError,
    manager::{ERR_NO_PRICE_DATA, ERR_NO_WALLET},
};

use super::{HandshakeExecutor, ERR_NO_ORDER};

/// Error emitted when joining to a task execution fails
const ERR_TASK_EXECUTION: &str = "settle-match-internal task failed";
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
    pub(super) async fn run_internal_matching_engine(
        &self,
        order: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        log::info!("Running internal matching engine on order {order}");
        // Lookup the order and its wallet
        let (network_order, wallet) = self.fetch_order_and_wallet(&order).await?;
        let my_order = wallet
            .orders
            .get(&network_order.id)
            .ok_or_else(|| HandshakeManagerError::StateNotFound(ERR_NO_ORDER.to_string()))?;
        let (my_proof, my_witness) =
            self.get_validity_proof_and_witness(&network_order.id).await.ok_or_else(|| {
                HandshakeManagerError::StateNotFound(ERR_MISSING_PROOFS.to_string())
            })?;

        // Fetch all other orders that are ready for matches
        let other_orders =
            self.global_state.read_order_book().await.get_local_scheduleable_orders().await;

        // Sample a price to match the order at
        let (base, quote) = self.token_pair_for_order(my_order);
        let price = self
            .fetch_price_vector()
            .await?
            .find_pair(&base, &quote)
            .ok_or_else(|| HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string()))?
            .2; // (base, quote, price)
        let price = FixedPoint::from_f64_round_down(price);

        // Shuffle the ordering of the other orders for fairness
        let mut rng = thread_rng();
        let mut shuffled_indices = (0..other_orders.len()).collect_vec();
        shuffled_indices.shuffle(&mut rng);

        // Match against each other order in the local book
        for order_id in shuffled_indices.into_iter().map(|ind| &other_orders[ind]) {
            // Same order
            if network_order.id == *order_id {
                continue;
            }

            // Same wallet
            let wallet_id = self
                .global_state
                .read_wallet_index()
                .await
                .get_wallet_for_order(order_id)
                .ok_or_else(|| HandshakeManagerError::StateNotFound(ERR_NO_WALLET.to_string()))?;
            if wallet_id == wallet.wallet_id {
                continue;
            }

            // Lookup the witness used for this order
            let (other_proof, other_witness) =
                match self.get_validity_proof_and_witness(order_id).await {
                    Some(proof) => proof,
                    None => continue,
                };

            // Lookup the other order and match on it
            let res = match self.global_state.get_order(order_id).await {
                Some(order) => match_orders(
                    my_order,
                    &order,
                    &my_witness.commitment_witness.balance_send.to_base_type(),
                    &other_witness.commitment_witness.balance_send.to_base_type(),
                    price,
                ),
                None => continue,
            };

            // Settle the match if the two orders cross
            if let Some(handshake_result) = res {
                // Spawn a task to settle the locally discovered match
                log::info!("internal match found for {order_id:?}, settling...");
                let task = SettleMatchInternalTask::new(
                    price,
                    network_order.id,
                    *order_id,
                    my_proof.clone(),
                    my_witness.clone(),
                    other_proof,
                    other_witness,
                    handshake_result,
                    self.starknet_client.clone(),
                    self.network_channel.clone(),
                    self.global_state.clone(),
                    self.proof_manager_work_queue.clone(),
                )
                .await
                .map_err(|_| HandshakeManagerError::TaskError(ERR_TASK_EXECUTION.to_string()))?;

                let (_, join_handle) = self.task_driver.start_task(task).await;

                // If the task errors, log the error and continue
                if !join_handle
                    .await
                    .map_err(|_| HandshakeManagerError::TaskError(ERR_TASK_EXECUTION.to_string()))?
                {
                    log::error!("internal match settlement failed for {order_id:?}");
                    continue;
                } else {
                    // The settlement job will have created a job to run the matching engine
                    // recursively on the now-updated wallet, return instead of continuing
                    return Ok(());
                }
            }
        }

        log::info!("No internal matches found for {order:?}");
        Ok(())
    }

    /// Get the validity proof and witness for a given order
    async fn get_validity_proof_and_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<(OrderValidityProofBundle, OrderValidityWitnessBundle)> {
        let locked_order_book = self.global_state.read_order_book().await;
        let proof = locked_order_book.get_validity_proofs(order_id).await?;
        let witness = locked_order_book.get_validity_proof_witnesses(order_id).await?;

        Some((proof, witness))
    }

    /// Fetch the order and wallet for the given order identifier
    async fn fetch_order_and_wallet(
        &self,
        order: &OrderIdentifier,
    ) -> Result<(NetworkOrder, Wallet), HandshakeManagerError> {
        let order = self
            .global_state
            .read_order_book()
            .await
            .get_order_info(order)
            .await
            .ok_or_else(|| HandshakeManagerError::StateNotFound(ERR_NO_ORDER.to_string()))?;

        let locked_wallet_index = self.global_state.read_wallet_index().await;
        let wallet = match locked_wallet_index.get_wallet_for_order(&order.id) {
            Some(wallet) => locked_wallet_index.get_wallet(&wallet).await,
            None => None,
        }
        .ok_or_else(|| HandshakeManagerError::StateNotFound(ERR_NO_WALLET.to_string()))?;

        Ok((order, wallet))
    }
}
