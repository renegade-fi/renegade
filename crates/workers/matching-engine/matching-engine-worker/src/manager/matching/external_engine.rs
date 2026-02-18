//! The matching engine for external matches
//!
//! An external match is one that occurs between an internal party (with state
//! allocated in the darkpool) and an external party (with no state in the
//! darkpool).
//!
//! The external matching engine is responsible for matching an external order
//! against all known internal order

use std::ops::RangeInclusive;

use circuit_types::Amount;
use darkpool_types::bounded_match_result::BoundedMatchResult;
use job_types::matching_engine::ExternalMatchingEngineOptions;
use system_bus::SystemBusMessage;
use tracing::{info, instrument, warn};
use types_account::{account::OrderId, order::Order};

use types_tasks::SettleExternalMatchTaskDescriptor;

use crate::{error::MatchingEngineError, executor::MatchingEngineExecutor};
use matching_engine_core::SuccessfulMatch;

/// The maximum one-sided range to allow on a malleable match
///
/// That is, when emitting a bounded match, the range of the match is:
///     [amount * (1 - MAX_MALLEABLE_RANGE), amount * (1 + MAX_MALLEABLE_RANGE)]
///
/// Note that the resulting bounded match may be clamped to a narrower range by
/// limits on the counterparty order
const MAX_MALLEABLE_RANGE: f64 = 0.1; // 10%

impl MatchingEngineExecutor {
    /// Encapsulates the logic for the external matching engine in an error
    /// handler
    ///
    /// This allows the engine to respond to the client through the bus even if
    /// the matching engine fails
    #[instrument(name = "run_external_matching_engine", skip_all)]
    pub async fn run_external_matching_engine(
        &self,
        order: Order,
        response_topic: String,
        options: ExternalMatchingEngineOptions,
    ) -> Result<(), MatchingEngineError> {
        // Check if either asset in the pair is disabled for matching
        let pair = order.pair();
        if self.is_asset_disabled(&pair.in_token) || self.is_asset_disabled(&pair.out_token) {
            warn!("Asset disabled for matching, skipping external matching engine...");
            self.handle_no_match(response_topic);
            return Ok(());
        }

        let matching_pool = options.matching_pool.clone();
        let price = options.price;
        let res = self.find_external_match(&order, matching_pool, price)?;
        let successful_match = match res {
            Some(match_res) => match_res,
            None => {
                self.handle_no_match(response_topic);
                return Ok(());
            },
        };

        // Handle a successful match
        if options.only_quote {
            self.forward_quote(response_topic.clone(), successful_match);
            Ok(())
        } else {
            self.try_settle_external_match(successful_match, response_topic, &options).await
        }
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        match_result: SuccessfulMatch,
        response_topic: String,
        _options: &ExternalMatchingEngineOptions,
    ) -> Result<(), MatchingEngineError> {
        // Look up the account ID for the internal order
        let internal_order_id = match_result.other_order_id;
        let account_id =
            self.state.get_account_id_for_order(&internal_order_id).await?.ok_or_else(|| {
                MatchingEngineError::state(format!(
                    "no account id found for order {internal_order_id:?}"
                ))
            })?;

        // Extract the amount in from the match result
        let internal_obligation = match_result.match_result.party1_obligation();
        let amount_in = internal_obligation.amount_in;

        // Compute the bounded match result and build a task descriptor
        let bounded_match_result = self.compute_bounded_match_result(&match_result).await?;
        let descriptor = SettleExternalMatchTaskDescriptor {
            account_id,
            order_id: internal_order_id,
            // This is the amount in for the internal party at the requested trade size
            amount_in,
            match_result: bounded_match_result,
            response_topic,
            validity_window_blocks: self.external_match_validity_window,
        };

        // Enqueue the task directly with the driver
        self.forward_bypassing_task(descriptor.into()).await
    }

    // --- Bounded Match Handling --- //

    /// Compute a bounded match result from a successful match
    async fn compute_bounded_match_result(
        &self,
        successful_match: &SuccessfulMatch,
    ) -> Result<BoundedMatchResult, MatchingEngineError> {
        let other_id = successful_match.other_order_id;
        let (order, matchable) = self.get_order_and_matchable_amount(other_id).await?;
        let min_fill = order.metadata.min_fill_size;

        // Internal party's amount in
        let internal_obligation = successful_match.match_result.party1_obligation();
        let match_amt = internal_obligation.amount_in;
        let fill_range = min_fill..=matchable;
        let (min_amount, max_amount) = self.derive_match_bounds(match_amt, fill_range)?;

        // The match price is in external party's output/input units, invert it to get
        // internal party's output/input units
        let internal_price = successful_match.price.price.inverse().expect("match price is zero");

        Ok(BoundedMatchResult {
            internal_party_input_token: internal_obligation.input_token,
            internal_party_output_token: internal_obligation.output_token,
            min_internal_party_amount_in: min_amount,
            max_internal_party_amount_in: max_amount,
            price: internal_price,
            // This field is set by the settlement task
            block_deadline: 0,
        })
    }

    /// Derive the bounds for a match
    ///
    /// Returns a tuple containing the minimum and maximum input amounts for the
    /// internal party.
    ///
    /// The `matchable_amount_bounds` are in terms of the internal party's input
    /// token (i.e., what they're selling).
    fn derive_match_bounds(
        &self,
        match_amt: Amount,
        matchable_amount_bounds: RangeInclusive<Amount>,
    ) -> Result<(Amount, Amount), MatchingEngineError> {
        let internal_party_min = *matchable_amount_bounds.start();
        let internal_party_max = *matchable_amount_bounds.end();

        let min_amount = mul_amount_f64(match_amt, 1.0 - MAX_MALLEABLE_RANGE);
        let max_amount = mul_amount_f64(match_amt, 1.0 + MAX_MALLEABLE_RANGE);

        // Clamp the amounts to the internal order's min and max fill
        let min_amount = u128::max(min_amount, internal_party_min);
        let max_amount = u128::min(max_amount, internal_party_max);
        if min_amount > max_amount {
            return Err(MatchingEngineError::NoValidBounds);
        }

        Ok((min_amount, max_amount))
    }

    // --- Quote Handling --- //

    /// Forward a quote to the client
    #[allow(clippy::needless_pass_by_value)]
    fn forward_quote(&self, response_topic: String, res: SuccessfulMatch) {
        info!("forwarding quote to client");
        // We don't need to expose input bounds for a quote, we just treat the requested
        // amount as an exact trade amount and return an exact-sized bundle.
        // The assemble endpoint will generate matchable bounds for a bundle.
        let internal_obligation = res.match_result.party1_obligation();
        let internal_price = res.price.price.inverse().expect("match price is zero");
        let quote = BoundedMatchResult {
            internal_party_input_token: internal_obligation.input_token,
            internal_party_output_token: internal_obligation.output_token,
            min_internal_party_amount_in: internal_obligation.amount_in,
            max_internal_party_amount_in: internal_obligation.amount_in,
            price: internal_price,
            // We also don't specify a block deadline for a quote,
            // Only assembled bundles have a block deadline attached
            block_deadline: 0,
        };
        let message = SystemBusMessage::ExternalOrderQuote { quote };
        self.system_bus.publish(response_topic, message);
    }

    /// Send a message on the response topic indicating that no match was found
    fn handle_no_match(&self, response_topic: String) {
        info!("no match found for external order");
        let response = SystemBusMessage::NoExternalMatchFound;
        self.system_bus.publish(response_topic, response);
    }

    // --- Helpers --- //

    /// Get an order and its matchable amount from an order ID
    async fn get_order_and_matchable_amount(
        &self,
        order_id: OrderId,
    ) -> Result<(Order, Amount), MatchingEngineError> {
        self.state.get_account_order_and_matchable_amount(&order_id).await?.ok_or_else(|| {
            MatchingEngineError::state(format!(
                "no order or matchable amount found for order {order_id:?}"
            ))
        })
    }
}

// --- Non-Member Helpers --- //

/// Multiply an `Amount` by an `f64` and round down to an `Amount`
fn mul_amount_f64(amount: Amount, multiplier: f64) -> Amount {
    let amount_f64 = amount as f64;
    let product = amount_f64 * multiplier;
    product.floor() as Amount
}
