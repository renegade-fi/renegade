//! The matching engine for external matches
//!
//! An external match is one that occurs between an internal party (with state
//! allocated in the darkpool) and an external party (with no state in the
//! darkpool).
//!
//! The external matching engine is responsible for matching an external order
//! against all known internal order

use std::collections::HashSet;

use circuit_types::{balance::Balance, fixed_point::FixedPoint, r#match::MatchResult};
use common::types::{
    tasks::SettleExternalMatchTaskDescriptor,
    token::Token,
    wallet::{Order, OrderIdentifier},
    TimestampedPrice,
};
use constants::Scalar;
use external_api::bus_message::SystemBusMessage;
use job_types::task_driver::TaskDriverJob;
use renegade_crypto::fields::scalar_to_u128;
use tracing::{error, info, instrument};
use util::err_str;

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

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
    ) -> Result<(), HandshakeManagerError> {
        match self.run_external_matching_engine_inner(order, response_topic.clone()).await {
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
        let mut matchable_orders = self.get_external_match_candidates().await?;
        let ts_price = self.get_execution_price(&base, &quote).await?;
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
            let settle_res = self
                .try_settle_external_match(
                    other_order_id,
                    ts_price,
                    match_res,
                    response_topic.clone(),
                )
                .await;

            match settle_res {
                Ok(()) => {
                    // Stop matching if a match was found
                    return Ok(());
                },
                Err(e) => {
                    error!(
                        "external match settlement failed on internal order {}: {e}",
                        other_order_id,
                    );
                },
            }

            // If matching failed, remove the other order from the candidate set
            matchable_orders.remove(&other_order_id);
        }

        self.handle_no_match(response_topic);
        Ok(())
    }

    /// Get the match candidates for an external order
    async fn get_external_match_candidates(
        &self,
    ) -> Result<HashSet<OrderIdentifier>, HandshakeManagerError> {
        let matchable_orders = self.state.get_externally_matchable_orders().await?;
        Ok(HashSet::from_iter(matchable_orders))
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        internal_order_id: OrderIdentifier,
        price: TimestampedPrice,
        match_res: MatchResult,
        response_topic: String,
    ) -> Result<(), HandshakeManagerError> {
        let wallet_id = self.get_wallet_id_for_order(&internal_order_id).await?;
        let task = SettleExternalMatchTaskDescriptor::new(
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
