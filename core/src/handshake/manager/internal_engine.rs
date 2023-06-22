//! Defines logic for running the internal matching engine on a given order

use circuits::{
    traits::LinkableType,
    types::{
        balance::Balance,
        order::{Order, OrderSide},
        r#match::MatchResult,
    },
    zk_gadgets::fixed_point::FixedPoint,
};
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use rand::{seq::SliceRandom, thread_rng};
use tracing::log;

use crate::{
    handshake::{
        error::HandshakeManagerError,
        manager::{ERR_NO_PRICE_DATA, ERR_NO_WALLET},
    },
    proof_generation::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    state::{wallet::Wallet, NetworkOrder, OrderIdentifier},
    tasks::settle_match_internal::SettleMatchInternalTask,
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
    /// global state, but this would require further denormalizing the order book
    /// index. We will hold off on this optimization until we either:
    ///     1. Determine this code path to be a bottleneck
    ///     2. Have a better state management abstraction that makes denormalization easier
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
        let (my_proof, my_witness) = self
            .get_validity_proof_and_witness(&network_order.id)
            .await
            .ok_or_else(|| HandshakeManagerError::StateNotFound(ERR_MISSING_PROOFS.to_string()))?;

        // Fetch all other orders that are ready for matches
        let other_orders = self
            .global_state
            .read_order_book()
            .await
            .get_local_scheduleable_orders()
            .await;

        // Sample a price to match the order at
        let (base, quote) = self.token_pair_for_order(my_order);
        let price = self
            .fetch_price_vector()
            .await?
            .find_pair(&base, &quote)
            .ok_or_else(|| HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string()))?
            .2; /* (base, quote, price) */
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
                    price,
                    my_order,
                    &my_witness.commitment_witness.balance_send.to_base_type(),
                    &order,
                    &other_witness.commitment_witness.balance_send.to_base_type(),
                ),
                None => continue,
            }?;

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
                .map_err(|err| HandshakeManagerError::TaskError(err.to_string()))?;

                let (_, join_handle) = self.task_driver.start_task(task).await;

                // If the task errors, log the error and continue
                if !join_handle
                    .await
                    .map_err(|_| HandshakeManagerError::TaskError(ERR_TASK_EXECUTION.to_string()))?
                {
                    log::error!("internal match settlement failed for {order_id:?}");
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Get the validity proof and witness for a given order
    async fn get_validity_proof_and_witness(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<(OrderValidityProofBundle, OrderValidityWitnessBundle)> {
        let locked_order_book = self.global_state.read_order_book().await;
        let proof = locked_order_book.get_validity_proofs(order_id).await?;
        let witness = locked_order_book
            .get_validity_proof_witnesses(order_id)
            .await?;

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

// -----------
// | Helpers |
// -----------

/// Match a given order against all other orders in the wallet
fn match_orders(
    midpoint_price: FixedPoint,
    order1: &Order,
    balance1: &Balance,
    order2: &Order,
    balance2: &Balance,
) -> Result<Option<MatchResult>, HandshakeManagerError> {
    // Same asset pair
    let mut valid_match = order1.base_mint == order2.base_mint
        && order1.quote_mint == order2.quote_mint
        && order1.side != order2.side;

    // Validate that the midpoint price is acceptable for both orders
    valid_match = valid_match
        && order1.price_in_range(midpoint_price)
        && order2.price_in_range(midpoint_price);

    if !valid_match {
        return Ok(None);
    }

    // Match the orders
    let party0_max_amount = compute_max_amount(&midpoint_price, order1, balance1);
    let party1_max_amount = compute_max_amount(&midpoint_price, order2, balance2);
    let min_base_amount = u64::min(party0_max_amount, party1_max_amount);

    let quote_amount = midpoint_price * Scalar::from(min_base_amount);
    let quote_amount = scalar_to_u64(&quote_amount.floor());
    let max_minus_min_amount = u64::max(party0_max_amount, party1_max_amount) - min_base_amount;

    Ok(Some(MatchResult {
        base_mint: order1.base_mint.clone(),
        quote_mint: order1.quote_mint.clone(),
        base_amount: min_base_amount,
        quote_amount,
        direction: order1.side.into(),
        max_minus_min_amount,
        min_amount_order_index: if party0_max_amount <= party1_max_amount {
            0
        } else {
            1
        },
    }))
}

/// Compute the maximum matchable amount for an order and balance
fn compute_max_amount(price: &FixedPoint, order: &Order, balance: &Balance) -> u64 {
    match order.side {
        // Buy the base, the max amount is possibly limited by the quote
        // balance
        OrderSide::Buy => {
            let price_f64 = price.to_f64();
            let balance_limit = (balance.amount as f64 / price_f64).floor() as u64;
            u64::min(order.amount, balance_limit)
        }
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => u64::min(order.amount, balance.amount),
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use circuits::types::{
        balance::Balance,
        order::{Order, OrderSide},
    };

    use crate::handshake::manager::internal_engine::match_orders;

    // --------------
    // | Dummy Data |
    // --------------

    /// The worst case price for the buy side
    const BUY_SIDE_WORST_CASE_PRICE: f32 = 10.;
    /// The worst case price for the sell side
    const SELL_SIDE_WORST_CASE_PRICE: f32 = 5.;

    lazy_static! {
        /// The first dummy order used in a valid match
        static ref ORDER1: Order = Order {
            base_mint: 1u64.into(),
            quote_mint: 2u64.into(),
            side: OrderSide::Buy,
            amount: 50,
            worst_case_price: BUY_SIDE_WORST_CASE_PRICE.into(),
            timestamp: 0,
        };

        /// The first dummy balance used in a valid match
        static ref BALANCE1: Balance = Balance {
            mint: 2u64.into(),
            amount: 500u64,
        };

        /// The second dummy order used in a valid match
        static ref ORDER2: Order = Order {
            base_mint: 1u64.into(),
            quote_mint: 2u64.into(),
            side: OrderSide::Sell,
            amount: 100,
            worst_case_price: SELL_SIDE_WORST_CASE_PRICE.into(),
            timestamp: 0,
        };

        /// The second dummy balance used in a valid match
        static ref BALANCE2: Balance = Balance {
            mint: 1u64.into(),
            amount: 100u64,
        };
    }

    // ---------
    // | Tests |
    // ---------

    /// Test a valid match between two orders
    #[test]
    fn test_valid_match() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_some());
        let res = res.unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 50);
        assert_eq!(
            res.quote_amount,
            350 /* midpoint_price * base_amount */
        );
        assert_eq!(res.direction, 0);
        assert_eq!(res.max_minus_min_amount, 50);
        assert_eq!(res.min_amount_order_index, 0);
    }

    /// Test a valid match between two order where the buy side is undercapitalized
    #[test]
    fn test_valid_match_undercapitalized_buy() {
        let order1 = ORDER1.clone();
        let mut balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        // Can only buy 10 units of the base
        balance1.amount = (midpoint_price * 10.) as u64;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_some());
        let res = res.unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction, 0);
        assert_eq!(res.max_minus_min_amount, 90);
        assert_eq!(res.min_amount_order_index, 0);
    }

    /// Test a valid match between two order where the sell side is undercapitalized
    #[test]
    fn test_valid_match_undercapitalized_sell() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let mut balance2 = BALANCE2.clone();
        let midpoint_price = 7.;

        // Can only sell 10 units of the base
        balance2.amount = 10u64;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_some());
        let res = res.unwrap();

        assert_eq!(res.base_mint, 1u64.into());
        assert_eq!(res.quote_mint, 2u64.into());
        assert_eq!(res.base_amount, 10);
        assert_eq!(res.quote_amount, 70 /* midpoint_price * base_amount */);
        assert_eq!(res.direction, 0);
        assert_eq!(res.max_minus_min_amount, 40);
        assert_eq!(res.min_amount_order_index, 1);
    }

    /// Test mismatched base mints
    #[test]
    fn test_mismatched_base_mints() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.base_mint = 3u64.into();
        let midpoint_price = 7.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_none());
    }

    /// Test mismatched quote mints
    #[test]
    fn test_mismatched_quote_mints() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.quote_mint = 3u64.into();
        let midpoint_price = 7.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_none());
    }

    /// Test two orders on the same side of the book
    #[test]
    fn test_same_side() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let mut order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        order2.side = order1.side;
        let midpoint_price = 7.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_none());
    }

    /// Test a midpoint price out of the buy side range
    #[test]
    fn test_buy_price_out_of_range() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        let midpoint_price = BUY_SIDE_WORST_CASE_PRICE + 1.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_none());
    }

    /// Test a midpoint price out of the sell side range
    #[test]
    fn test_sell_price_out_of_range() {
        let order1 = ORDER1.clone();
        let balance1 = BALANCE1.clone();
        let order2 = ORDER2.clone();
        let balance2 = BALANCE2.clone();

        let midpoint_price = SELL_SIDE_WORST_CASE_PRICE - 1.;

        let res = match_orders(
            midpoint_price.into(),
            &order1,
            &balance1,
            &order2,
            &balance2,
        )
        .unwrap();

        assert!(res.is_none());
    }
}
