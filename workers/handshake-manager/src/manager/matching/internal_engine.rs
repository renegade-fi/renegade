//! Defines logic for running the internal matching engine on a given order

use std::collections::HashSet;

use circuit_types::{fixed_point::FixedPoint, r#match::MatchResult};
use common::types::{
    network_order::NetworkOrder,
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    tasks::{SettleMatchInternalTaskDescriptor, TaskDescriptor},
    wallet::{Order, OrderIdentifier, Wallet, WalletIdentifier},
    TimestampedPrice,
};
use job_types::task_driver::TaskDriverJob;
use tracing::{error, info, instrument};
use util::err_str;

use crate::{
    error::HandshakeManagerError,
    manager::{
        handshake::{ERR_NO_ORDER, ERR_NO_WALLET},
        HandshakeExecutor,
    },
};

use super::matching_order_filter;

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
    #[instrument(name = "run_internal_matching_engine", skip_all)]
    pub async fn run_internal_matching_engine(
        &self,
        order_id: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        info!("Running internal matching engine on order {order_id}");
        // Lookup the order and its wallet
        let (network_order, wallet) = self.fetch_order_and_wallet(&order_id).await?;
        let my_order = wallet
            .orders
            .get(&network_order.id)
            .cloned()
            .ok_or_else(|| HandshakeManagerError::State(ERR_NO_ORDER.to_string()))?;
        let sell_mint = my_order.send_mint();
        let my_balance = wallet.get_balance_or_default(sell_mint);

        // Sample a price to match the order at
        let ts_price = self.get_execution_price_for_order(&network_order.id).await?;
        let price = FixedPoint::from_f64_round_down(ts_price.price);

        // Try to find a match iteratively, we wrap this in a retry loop in case
        // settlement fails on a match
        let mut match_candidates =
            self.get_internal_match_candidates(order_id, &my_order, &wallet).await?;
        while !match_candidates.is_empty() {
            let (other_order_id, match_res) = match self
                .find_match(&my_order, &my_balance, price, match_candidates.clone())
                .await?
            {
                Some(match_res) => match_res,
                None => {
                    info!("No internal matches found for {order_id:?}");
                    return Ok(());
                },
            };

            // Try to settle the match
            match self.try_settle_match(order_id, other_order_id, ts_price, match_res).await {
                Ok(()) => {
                    // Stop matching if a match was found
                    return Ok(());
                },
                Err(e) => {
                    error!(
                        "internal match settlement failed for {} x {}: {e}",
                        network_order.id, order_id,
                    );

                    // Check whether matching should continue
                    if !self.wallet_still_valid(&wallet).await? {
                        info!("wallet has changed, stopping internal matching engine...");
                        return Ok(());
                    }
                },
            }

            // If matching failed, remove the other order from the candidate set
            match_candidates.remove(&other_order_id);
        }

        Ok(())
    }

    /// Get the set of match candidates for an order
    ///
    /// Shuffles the ordering of the other orders for fairness
    async fn get_internal_match_candidates(
        &self,
        order_id: OrderIdentifier,
        order: &Order,
        wallet: &Wallet,
    ) -> Result<HashSet<OrderIdentifier>, HandshakeManagerError> {
        // Filter by matching pool
        let my_pool_name = self.state.get_matching_pool_for_order(&order_id).await?;
        let filter = matching_order_filter(order, false /* external */);
        let other_orders =
            self.state.get_matchable_orders_in_matching_pool(my_pool_name, filter).await?;
        let mut orders_set = HashSet::from_iter(other_orders);

        // Filter out orders from the same wallet
        let wallet_order_ids = wallet.orders.keys();
        for order_id in wallet_order_ids {
            orders_set.remove(order_id);
        }

        Ok(orders_set)
    }

    /// Try a match and settle it if the two orders cross
    async fn try_settle_match(
        &self,
        order_id1: OrderIdentifier,
        order_id2: OrderIdentifier,
        price: TimestampedPrice,
        match_result: MatchResult,
    ) -> Result<(), HandshakeManagerError> {
        // Fetch state elements needed for settlement
        let wallet_id1 = self.get_wallet_id_for_order(&order_id1).await?;
        let wallet_id2 = self.get_wallet_id_for_order(&order_id2).await?;
        let (validity_proof1, validity_witness1) =
            self.get_validity_proof_and_witness(&order_id1).await?;
        let (validity_proof2, validity_witness2) =
            self.get_validity_proof_and_witness(&order_id2).await?;

        // Submit the match to the task driver
        let task: TaskDescriptor = SettleMatchInternalTaskDescriptor::new(
            price,
            order_id1,
            order_id2,
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

        let (job, rx) = TaskDriverJob::new_immediate_with_notification(task);
        self.task_queue.send(job).map_err(err_str!(HandshakeManagerError::TaskError))?;

        rx.await
            .map_err(err_str!(HandshakeManagerError::TaskError))? // RecvError
            .map_err(err_str!(HandshakeManagerError::TaskError)) // TaskDriverError
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the validity proof and witness for a given order
    async fn get_validity_proof_and_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<(OrderValidityProofBundle, OrderValidityWitnessBundle), HandshakeManagerError> {
        let state = &self.state;
        let proof = state
            .get_validity_proofs(order_id)
            .await?
            .ok_or_else(|| HandshakeManagerError::state(ERR_MISSING_PROOFS))?;
        let witness = state
            .get_validity_proof_witness(order_id)
            .await?
            .ok_or_else(|| HandshakeManagerError::state(ERR_MISSING_PROOFS))?;

        Ok((proof, witness))
    }

    /// Get the wallet for an order
    pub(crate) async fn get_wallet_id_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<WalletIdentifier, HandshakeManagerError> {
        self.state
            .get_wallet_id_for_order(order_id)
            .await?
            .ok_or_else(|| HandshakeManagerError::state(ERR_NO_WALLET))
    }

    /// Fetch the order and wallet for the given order identifier
    async fn fetch_order_and_wallet(
        &self,
        order: &OrderIdentifier,
    ) -> Result<(NetworkOrder, Wallet), HandshakeManagerError> {
        let state = &self.state;
        let order = state
            .get_order(order)
            .await?
            .ok_or_else(|| HandshakeManagerError::State(ERR_NO_ORDER.to_string()))?;

        let wallet = match state.get_wallet_for_order(&order.id).await? {
            Some(wallet) => wallet,
            None => return Err(HandshakeManagerError::State(ERR_NO_WALLET.to_string())),
        };

        Ok((order, wallet))
    }

    /// Check whether a wallet is still valid. This amounts to checking:
    ///     1. Whether the wallet's known nullifier is still valid. This may be
    ///        false if the wallet has been updated since a match was attempted
    ///     2. Whether the wallet's queue is still empty and unpaused.
    ///        Concurrent matches from elsewhere in the relayer may cause this
    ///        second condition to be false
    ///
    /// This check may be executed after a match settlement fails
    async fn wallet_still_valid(&self, wallet: &Wallet) -> Result<bool, HandshakeManagerError> {
        // Check the nullifier
        let new_wallet = self.state.get_wallet(&wallet.wallet_id).await?;
        let nullifier = new_wallet.map(|w| w.get_wallet_nullifier()).unwrap_or_default();
        if wallet.get_wallet_nullifier() != nullifier {
            return Ok(false);
        }

        // Check the queue
        let queue_len = self.state.get_task_queue_len(&wallet.wallet_id).await?;
        if queue_len > 0 {
            return Ok(false);
        }

        if self.state.is_queue_paused(&wallet.wallet_id).await? {
            return Ok(false);
        }

        Ok(true)
    }
}
