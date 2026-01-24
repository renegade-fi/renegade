//! The matching engine for external matches
//!
//! An external match is one that occurs between an internal party (with state
//! allocated in the darkpool) and an external party (with no state in the
//! darkpool).
//!
//! The external matching engine is responsible for matching an external order
//! against all known internal order

use std::ops::RangeInclusive;

use circuit_types::{Amount, fixed_point::FixedPoint};
use crypto::fields::scalar_to_u128;
use job_types::matching_engine::ExternalMatchingEngineOptions;
use system_bus::SystemBusMessage;
use tracing::{info, instrument};
use types_account::{account::OrderId, order::Order};
use types_core::MatchResult;

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
        let matching_pool = options.matching_pool();
        let res = self.find_external_match(&order, matching_pool)?;
        let successful_match = match res {
            Some(match_res) => match_res,
            None => {
                self.handle_no_match(response_topic);
                return Ok(());
            },
        };

        // Handle a successful match
        if options.only_quote {
            self.forward_quote(response_topic.clone(), successful_match.match_result);
            Ok(())
        } else {
            self.try_settle_external_match(order.id, successful_match, response_topic, &options)
                .await
        }
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        internal_order_id: OrderId,
        match_result: SuccessfulMatch,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), MatchingEngineError> {
        todo!("Settle external match")
    }

    // --- Bounded Match Handler --- //

    /// Derive the bounds for a match
    ///
    /// Returns a tuple containing the minimum and maximum input amounts for the
    /// external party.
    async fn derive_match_bounds(
        &self,
        price: FixedPoint,
        match_amt: Amount,
        matchable_amount_bounds: RangeInclusive<Amount>,
    ) -> Result<(Amount, Amount), MatchingEngineError> {
        let counterparty_min = *matchable_amount_bounds.start();
        let counterparty_max = *matchable_amount_bounds.end();
        let min_input = price.ceil_div_int(counterparty_min);
        let max_input = price.floor_div_int(counterparty_max);

        let min_amount = mul_amount_f64(match_amt, 1.0 - MAX_MALLEABLE_RANGE);
        let max_amount = mul_amount_f64(match_amt, 1.0 + MAX_MALLEABLE_RANGE);

        // Clamp the amounts to the order's min and max
        let min_amount = u128::max(min_amount, scalar_to_u128(&min_input));
        let max_amount = u128::min(max_amount, scalar_to_u128(&max_input));
        if min_amount > max_amount {
            return Err(MatchingEngineError::NoValidBounds);
        }

        Ok((min_amount, max_amount))
    }

    // --- Helper Functions --- //

    /// Forward a quote to the client
    #[allow(clippy::needless_pass_by_value)]
    fn forward_quote(&self, response_topic: String, quote: MatchResult) {
        info!("forwarding quote to client");
        todo!("Forward quote")
    }

    /// Send a message on the response topic indicating that no match was found
    fn handle_no_match(&self, response_topic: String) {
        info!("no match found for external order");
        let response = SystemBusMessage::NoExternalMatchFound;
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
