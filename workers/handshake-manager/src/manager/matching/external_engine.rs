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
    token::Token,
    wallet::{Order, OrderIdentifier},
};
use constants::Scalar;
use job_types::{handshake_manager::ExternalMatchingResponse, ResponseSender};
use renegade_crypto::fields::scalar_to_u128;
use tracing::{error, info};

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

/// The response channel type for the external matching engine
type ExternalMatchResponseSender = ResponseSender<ExternalMatchingResponse>;

impl HandshakeExecutor {
    /// Execute an external match
    pub async fn run_external_matching_engine(
        &self,
        order: Order,
        response_channel: ExternalMatchResponseSender,
    ) -> Result<(), HandshakeManagerError> {
        let base = Token::from_addr_biguint(&order.base_mint);
        let quote = Token::from_addr_biguint(&order.quote_mint);
        info!(
            "Running external matching engine for {}/{}",
            base.get_ticker().unwrap_or_default(),
            quote.get_ticker().unwrap_or_default()
        );

        // Get all orders that consent to external matching
        let mut matchable_orders = self.get_external_match_candidates(&order).await?;
        let ts_price = self.get_execution_price(&base, &quote).await?;
        let price = FixedPoint::from_f64_round_down(ts_price.price);

        // Mock a balance for the external order, assuming it's fully capitalized
        let balance = self.mock_balance_for_external_order(&order, price);

        // Try to find a match iteratively, we wrap this in a retry loop in case
        // settlement fails on a match
        while !matchable_orders.is_empty() {
            let (other_order_id, match_res) =
                match self.find_match(&order, &balance, price, matchable_orders.clone()).await? {
                    Some(match_res) => match_res,
                    None => {
                        info!("No external matches found");
                        return Ok(());
                    },
                };

            // Try to settle the match
            match self.try_settle_external_match(other_order_id, match_res).await {
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

        // TODO: Send this when a match is found
        response_channel.send(()).expect("failed to send response");
        info!("no external matches found");
        Ok(())
    }

    /// Get the match candidates for an external order
    ///
    /// TODO: Replace this with a correct implementation that filters out orders
    /// which do not consent to external matching
    async fn get_external_match_candidates(
        &self,
        order: &Order,
    ) -> Result<HashSet<OrderIdentifier>, HandshakeManagerError> {
        let matchable_orders = self.state.get_locally_matchable_orders().await?;
        Ok(HashSet::from_iter(matchable_orders))
    }

    /// Settle an external match
    async fn try_settle_external_match(
        &self,
        internal_order_id: OrderIdentifier,
        match_res: MatchResult,
    ) -> Result<(), HandshakeManagerError> {
        // TODO: Implement this method
        todo!()
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
}
