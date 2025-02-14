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
    balance::Balance,
    fixed_point::FixedPoint,
    r#match::{ExternalMatchResult, MatchResult},
};
use common::types::{
    tasks::SettleExternalMatchTaskDescriptor,
    token::Token,
    wallet::{Order, OrderIdentifier},
    TimestampedPrice,
};
use constants::Scalar;
use external_api::bus_message::SystemBusMessage;
use job_types::{handshake_manager::ExternalMatchingEngineOptions, task_driver::TaskDriverJob};
use renegade_crypto::fields::scalar_to_u128;
use tracing::{error, info, instrument, warn};
use util::{err_str, telemetry::helpers::backfill_trace_field};

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

use super::matching_order_filter;

/// The maximum difference between the matched quote amount and the requested
/// exact amount that allows the quote amount to be overridden
///
/// This is intentionally very low, as the quote amount should only be
/// overridden for very small differences that amount to rounding
const MAX_QUOTE_OVERRIDE_DIFF: f64 = 0.000001;

impl HandshakeExecutor {
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
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        // Sample an execution price if one is not provided
        let ts_price = match options.price {
            Some(price) => price,
            None => {
                let base = Token::from_addr_biguint(&order.base_mint);
                let quote = Token::from_addr_biguint(&order.quote_mint);
                self.get_execution_price(&base, &quote).await?
            },
        };

        // Run the matching engine
        match self
            .run_external_matching_engine_inner(order, response_topic.clone(), ts_price, options)
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
        ts_price: TimestampedPrice,
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
        let mut matchable_orders = self.get_external_match_candidates(&order).await?;
        let price = ts_price.as_fixed_point();

        // Mock a balance for the external order, assuming it's fully capitalized
        let balance = self.mock_balance_for_external_order(&order, price);

        // Try to find a match iteratively, we wrap this in a retry loop in case
        // settlement fails on a match
        while !matchable_orders.is_empty() {
            let (other_order_id, mut match_res) =
                match self.find_match(&order, &balance, price, matchable_orders.clone()).await? {
                    Some(match_res) => match_res,
                    None => {
                        self.handle_no_match(response_topic);
                        return Ok(());
                    },
                };

            // For an external match, the direction of the match should always equal the
            // internal order's direction, make sure this is the case. The core engine logic
            // may match the external order as the first party
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
    ) -> Result<HashSet<OrderIdentifier>, HandshakeManagerError> {
        let filter = matching_order_filter(order, true /* external */);
        let matchable_orders = self.state.get_matchable_orders(filter).await?;
        backfill_trace_field("num_candidates", matchable_orders.len());
        Ok(HashSet::from_iter(matchable_orders))
    }

    /// Run a match against a single order
    async fn handle_match(
        &self,
        other_order_id: OrderIdentifier,
        price: TimestampedPrice,
        mut match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        // Possibly override the quote amount if an exact quote amount is specified
        self.maybe_override_quote_amount(&mut match_res, options);

        // If the request only requires a quote, we can stop here
        if options.only_quote {
            self.forward_quote(response_topic.clone(), match_res);
            return Ok(());
        }

        // Otherwise, settle the match by building an atomic match bundle
        let settle_res = self
            .try_settle_external_match(
                other_order_id,
                price,
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

    /// Possibly override the quote amount if an exact quote amount is specified
    /// and the amount may be overridden
    fn maybe_override_quote_amount(
        &self,
        match_res: &mut MatchResult,
        options: &ExternalMatchingEngineOptions,
    ) {
        let exact_quote = match options.exact_quote_amount {
            Some(amount) => amount,
            None => return,
        };

        let override_diff =
            (match_res.quote_amount as f64 - exact_quote as f64) / match_res.quote_amount as f64;
        if override_diff.abs() < MAX_QUOTE_OVERRIDE_DIFF {
            match_res.quote_amount = exact_quote;
        } else {
            warn!("quote difference too large, cannot override with exact quote amount")
        }
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        internal_order_id: OrderIdentifier,
        price: TimestampedPrice,
        match_res: MatchResult,
        response_topic: String,
        options: &ExternalMatchingEngineOptions,
    ) -> Result<(), HandshakeManagerError> {
        let wallet_id = self.get_wallet_id_for_order(&internal_order_id).await?;
        let task = SettleExternalMatchTaskDescriptor::new(
            options.bundle_duration,
            internal_order_id,
            wallet_id,
            price,
            match_res,
            response_topic,
        );

        let (job, rx) = TaskDriverJob::new_immediate_with_notification(task.into());
        self.task_queue.send(job).map_err(err_str!(HandshakeManagerError::SendMessage))?;
        rx.await
            .map_err(err_str!(HandshakeManagerError::TaskError))? // RecvError
            .map_err(err_str!(HandshakeManagerError::TaskError)) // TaskDriverError
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
