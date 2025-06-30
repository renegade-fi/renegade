//! The matching engine for external matches
//!
//! An external match is one that occurs between an internal party (with state
//! allocated in the darkpool) and an external party (with no state in the
//! darkpool).
//!
//! The external matching engine is responsible for matching an external order
//! against all known internal order

use std::collections::HashSet;

use circuit_types::{
    Amount,
    balance::Balance,
    fixed_point::FixedPoint,
    r#match::{BoundedMatchResult, ExternalMatchResult, MatchResult},
};
use common::types::{
    MatchingPoolName,
    price::TimestampedPriceFp,
    tasks::{
        SettleExternalMatchTaskDescriptor, SettleMalleableExternalMatchTaskDescriptor,
        TaskDescriptor,
    },
    token::Token,
    wallet::{Order, OrderIdentifier},
};
use constants::Scalar;
use external_api::bus_message::SystemBusMessage;
use job_types::handshake_manager::ExternalMatchingEngineOptions;
use renegade_crypto::fields::scalar_to_u128;
use tracing::{error, info, instrument};
use util::{matching_engine::compute_max_amount, telemetry::helpers::backfill_trace_field};

use crate::{
    error::HandshakeManagerError,
    manager::{
        HandshakeExecutor,
        handshake::{ERR_NO_ORDER, ERR_NO_WALLET},
    },
};

use super::matching_order_filter;

/// The maximum difference between the matched quote amount and the requested
/// exact amount that allows the quote amount to be overridden
///
/// This is intentionally very low, as the quote amount should only be
/// overridden for very small differences that amount to rounding
const MAX_PRICE_OVERRIDE_DIFF: f64 = 0.000001;
/// The maximum one-sided range to allow on a malleable match
///
/// That is, when emitting a bounded match, the range of the match is:
///     [amount * (1 - MAX_MALLEABLE_RANGE), amount * (1 + MAX_MALLEABLE_RANGE)]
///
/// Note that the resulting bounded match may be clamped to a narrower range by
/// limits on the counterparty order
const MAX_MALLEABLE_RANGE: f64 = 0.1; // 10%

impl HandshakeExecutor {
    /// Encapsulates the logic for the external matching engine in an error
    /// handler
    ///
    /// This allows the engine to respond to the client through the bus even if
    /// the matching engine fails
    #[instrument(name = "run_external_matching_engine", skip_all)]
    pub async fn run_external_matching_engine(
        &self,
        mut order: Order,
        response_topic: String,
        mut options: ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        // Sample an execution price if one is not provided
        let ts_price = match options.price {
            Some(price) => price.into(),
            None => {
                let base = Token::from_addr_biguint(&order.base_mint);
                let quote = Token::from_addr_biguint(&order.quote_mint);
                self.get_execution_price(&base, &quote).await?
            },
        };

        let ts_price = match self.setup_exact_quote_amount(ts_price, &mut order, &mut options)? {
            Some(price) => price,
            None => {
                self.handle_no_match(response_topic);
                return Ok(());
            },
        };

        // Run the matching engine
        match self
            .run_external_matching_engine_inner(order, response_topic.clone(), ts_price, &options)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                self.handle_no_match(response_topic);
                Err(e)
            },
        }
    }

    /// Execute an external match
    async fn run_external_matching_engine_inner(
        &self,
        order: Order,
        response_topic: String,
        ts_price: TimestampedPriceFp,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        let base = Token::from_addr_biguint(&order.base_mint);
        let quote = Token::from_addr_biguint(&order.quote_mint);
        info!(
            "Running external matching engine for {} {}/{} with size {}",
            order.side,
            base.get_ticker().unwrap_or_default(),
            quote.get_ticker().unwrap_or_default(),
            order.amount
        );

        // Get all orders that consent to external matching
        let pool = options.matching_pool.clone();
        let mut matchable_orders = self.get_external_match_candidates(&order, pool).await?;
        let price = ts_price.price;
        let min_quote = options.min_quote_amount.unwrap_or_default();

        // Mock a balance for the external order, assuming it's fully capitalized
        let balance = self.mock_balance_for_external_order(&order, price);

        // Try to find a match iteratively, we wrap this in a retry loop in case
        // settlement fails on a match
        while !matchable_orders.is_empty() {
            let res = self
                .find_match_with_min_quote_amount(
                    &order,
                    &balance,
                    price,
                    min_quote,
                    matchable_orders.iter(),
                )
                .await?;
            if res.is_none() {
                self.handle_no_match(response_topic);
                return Ok(());
            }

            // For an external match, the direction of the match should always equal the
            // internal order's direction, make sure this is the case. The core engine logic
            // may match the external order as the first party
            let (other_order_id, mut match_res) = res.unwrap();
            match_res.direction = order.side.opposite().match_direction();
            let id = other_order_id;
            let topic = response_topic.clone();
            if self.handle_match(id, ts_price, match_res, topic, options).await.is_ok() {
                return Ok(());
            }

            // If matching failed, remove the other order from the candidate set
            matchable_orders.remove(&other_order_id);
        }

        self.handle_no_match(response_topic);
        Ok(())
    }

    /// Get the match candidates for an external order
    #[instrument(name = "get_external_match_candidates", skip_all, fields(num_candidates))]
    async fn get_external_match_candidates(
        &self,
        order: &Order,
        matching_pool: Option<MatchingPoolName>,
    ) -> Result<HashSet<OrderIdentifier>, HandshakeManagerError> {
        let filter = matching_order_filter(order, true /* external */);
        let candidates = match matching_pool {
            Some(pool) => self.state.get_matchable_orders_in_matching_pool(pool, filter).await?,
            None => self.state.get_matchable_orders(filter).await?,
        };

        backfill_trace_field("num_candidates", candidates.len());
        Ok(HashSet::from_iter(candidates))
    }

    /// Handle a match against an order
    async fn handle_match(
        &self,
        order_id: OrderIdentifier,
        ts_price: TimestampedPriceFp,
        match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        if options.bounded_match {
            self.handle_bounded_match(order_id, ts_price, match_res, response_topic, options).await
        } else {
            self.handle_exact_match(order_id, ts_price, match_res, response_topic, options).await
        }
    }

    // --- Exact Match Handler -- //

    /// Handle an exact match result on the given order
    async fn handle_exact_match(
        &self,
        other_order_id: OrderIdentifier,
        ts_price: TimestampedPriceFp,
        match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        // If the request only requires a quote, we can stop here
        if options.only_quote {
            self.forward_quote(response_topic.clone(), match_res);
            return Ok(());
        }

        // Otherwise, settle the match by building an atomic match bundle
        let settle_res = self
            .try_settle_external_match(
                other_order_id,
                ts_price,
                match_res,
                response_topic.clone(),
                options,
            )
            .await;

        match settle_res {
            Ok(()) => Ok(()),
            Err(e) => {
                error!(
                    "external match settlement failed on internal order {}: {e}",
                    other_order_id,
                );
                Err(e)
            },
        }
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        internal_order_id: OrderIdentifier,
        ts_price: TimestampedPriceFp,
        match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        let wallet_id = self.get_wallet_id_for_order(&internal_order_id).await?;
        let task = SettleExternalMatchTaskDescriptor::new(
            options.bundle_duration,
            internal_order_id,
            wallet_id,
            ts_price,
            match_res,
            response_topic,
        );
        self.enqueue_settlement_task(task, options).await
    }

    // --- Bounded Match Handler --- //

    /// Handle a bounded match result on the given order
    ///
    /// The matching engine will sample appropriate bounds for the `base_amount`
    /// and forward the task to the task driver to create a bundle.
    async fn handle_bounded_match(
        &self,
        order_id: OrderIdentifier,
        ts_price: TimestampedPriceFp,
        match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        // Build a bounded match result
        let price_fp = ts_price.price();
        let (min_amount, max_amount) =
            self.derive_match_bounds(&order_id, price_fp, match_res.base_amount).await?;
        let bounded_res = BoundedMatchResult {
            quote_mint: match_res.quote_mint,
            base_mint: match_res.base_mint,
            price: price_fp,
            min_base_amount: min_amount,
            max_base_amount: max_amount,
            direction: match_res.direction,
        };

        // Create a task to settle the match
        let wallet_id = self.get_wallet_id_for_order(&order_id).await?;
        let task = SettleMalleableExternalMatchTaskDescriptor::new(
            options.bundle_duration,
            order_id,
            wallet_id,
            bounded_res,
            response_topic,
        );
        self.enqueue_settlement_task(task, options).await
    }

    /// Derive the bounds for a match
    ///
    /// Returns a tuple containing `(min_amount, max_amount)`
    async fn derive_match_bounds(
        &self,
        order_id: &OrderIdentifier,
        price: FixedPoint,
        match_amt: Amount,
    ) -> Result<(Amount, Amount), HandshakeManagerError> {
        let wallet = self
            .state
            .get_wallet_for_order(order_id)
            .await?
            .ok_or_else(|| HandshakeManagerError::state(ERR_NO_WALLET))?;
        let order = wallet
            .get_order(order_id)
            .ok_or_else(|| HandshakeManagerError::state(ERR_NO_ORDER))?
            .clone();

        let capitalizing_balance = wallet.get_balance_for_order(&order).unwrap_or_default();
        let order_min = order.min_fill_size;
        let order_max = compute_max_amount(&price, &order.into(), &capitalizing_balance);

        let min_amount = mul_amount_f64(match_amt, 1.0 - MAX_MALLEABLE_RANGE);
        let max_amount = mul_amount_f64(match_amt, 1.0 + MAX_MALLEABLE_RANGE);

        // Clamp the amounts to the order's min and max
        let min_amount = u128::max(min_amount, order_min);
        let max_amount = u128::min(max_amount, order_max);

        Ok((min_amount, max_amount))
    }

    // --- Helper Functions --- //

    /// Setup an exact quote amount
    ///
    /// This requires tweaking the order's base amount and the price at which
    /// the order executes. We verify that the tweaks do not move the price a
    /// material amount. If this is not possible, we return `None` to indicate
    /// that an exact match cannot be found
    ///
    /// The price returned is the price at which the match should execute in
    /// order to fulfill the quote amount constraints
    fn setup_exact_quote_amount(
        &self,
        original_price: TimestampedPriceFp,
        order: &mut Order,
        options: &mut ExternalMatchingEngineOptions,
    ) -> Result<Option<TimestampedPriceFp>, HandshakeManagerError> {
        // If no exact quote is configured, the original price will be used
        let quote_amount = match options.exact_quote_amount {
            Some(amount) => amount,
            None => return Ok(Some(original_price)),
        };
        let price_fp = original_price.price();

        // Compute a base amount that we will use to derive the modified price
        let base_amount_scalar = price_fp.ceil_div_int(quote_amount);
        let base_amount = scalar_to_u128(&base_amount_scalar);

        // Update the order and options to reflect the new amounts
        order.amount = base_amount;
        options.min_quote_amount = Some(quote_amount);

        // Compute the implied price for the new amounts
        let price_fp = compute_implied_price(base_amount, quote_amount);
        let new_price = TimestampedPriceFp::new(price_fp);
        if check_price_override_tolerance(new_price.price.to_f64(), original_price.price.to_f64()) {
            Ok(Some(new_price))
        } else {
            Ok(None)
        }
    }

    /// Enqueue a settlement task
    async fn enqueue_settlement_task<T: Into<TaskDescriptor>>(
        &self,
        descriptor: T,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        let descriptor = descriptor.into();
        if options.allow_shared {
            self.enqueue_concurrent_task_await_completion(descriptor).await
        } else {
            self.enqueue_serial_task_await_completion(descriptor).await
        }
    }

    /// Forward a quote to the client
    fn forward_quote(&self, response_topic: String, quote: MatchResult) {
        info!("forwarding quote to client");
        let external_res = ExternalMatchResult::from(quote);
        let response = SystemBusMessage::ExternalOrderQuote { quote: external_res };
        self.system_bus.publish(response_topic, response);
    }

    /// Mock a balance for an external order
    ///
    /// We cannot know the external party's balance here so we mock it for the
    /// matching engine. We assume the external order is fully capitalized and
    /// so we mock a full balance
    fn mock_balance_for_external_order(&self, order: &Order, price: FixedPoint) -> Balance {
        let base_amount = Scalar::from(order.amount);
        let quote_amount_fp = price * base_amount + Scalar::one();
        let quote_amount = quote_amount_fp.floor();

        let (mint, amount) = if order.side.is_buy() {
            (order.quote_mint.clone(), quote_amount)
        } else {
            (order.base_mint.clone(), base_amount)
        };

        Balance::new_from_mint_and_amount(mint, scalar_to_u128(&amount))
    }

    /// Send a message on the response topic indicating that no match was found
    fn handle_no_match(&self, response_topic: String) {
        info!("no match found for external order");
        let response = SystemBusMessage::NoAtomicMatchFound;
        self.system_bus.publish(response_topic, response);
    }
}

// --- Non-Member Helpers --- //

/// Multiply an `Amount` by an `f64` and round down to an `Amount`
fn mul_amount_f64(amount: Amount, multiplier: f64) -> Amount {
    let amount_f64 = amount as f64;
    let product = amount_f64 * multiplier;
    product.floor() as Amount
}

/// Compute the implied price for a given base and quote amount
///
/// We ceil div here because the `quote_amount` is constrained to equal the
/// floor div of the price times the `base_amount` in the matching engine
/// constraints. So we need `price * base_amount >= quote_amount` to hold.
fn compute_implied_price(base_amount: Amount, quote_amount: Amount) -> FixedPoint {
    let base_amount_fp = FixedPoint::from(base_amount);
    let quote_amount_fp = FixedPoint::from(quote_amount);
    quote_amount_fp.ceil_div(&base_amount_fp)
}

/// Check that two prices are within the price override tolerance
fn check_price_override_tolerance(new_price: f64, old_price: f64) -> bool {
    let override_diff = (new_price - old_price) / old_price;
    override_diff.abs() < MAX_PRICE_OVERRIDE_DIFF
}
