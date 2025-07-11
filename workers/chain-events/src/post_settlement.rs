//! Post-settlement helpers for external match processing
//!
//! This module holds a small immutable context struct (`PostSettlementCtx`) and
//! a set of methods on `OnChainEventListenerExecutor` that apply
//! post-settlement side-effects.

use crate::error::OnChainEventListenerError;
use crate::listener::OnChainEventListenerExecutor;
use circuit_types::{fees::FeeTake, fixed_point::FixedPoint, r#match::ExternalMatchResult};
use common::types::{
    price::TimestampedPrice,
    wallet::{OrderIdentifier, WalletIdentifier, order_metadata::OrderState},
};
use constants::EXTERNAL_MATCH_RELAYER_FEE;
use renegade_metrics;
use util::{
    matching_engine::compute_fee_obligation_with_protocol_fee, on_chain::get_external_match_fee,
};

/// The error message emitted when metadata for an order cannot be found
const ERR_NO_ORDER_METADATA: &str = "order metadata not found";

/// Bundle of data shared across post-settlement helpers
pub(crate) struct PostSettlementCtx<'a> {
    /// Wallet containing the internal order
    pub wallet_id: WalletIdentifier,
    /// The full external match result
    pub external_match_result: &'a ExternalMatchResult,
    /// Execution price (quote/base)
    pub price: TimestampedPrice,
}

impl<'a> PostSettlementCtx<'a> {
    /// Build a context from the external match
    pub fn new(
        wallet_id: WalletIdentifier,
        external_match_result: &'a ExternalMatchResult,
    ) -> Self {
        let price = execution_price(external_match_result);
        Self { wallet_id, external_match_result, price }
    }
}

// ----------------------------
// | Post-settlement helpers |
// ----------------------------

impl OnChainEventListenerExecutor {
    /// Record volume metrics for the match
    pub(crate) fn record_metrics(&self, ctx: &PostSettlementCtx<'_>) {
        let match_result = ctx.external_match_result.to_match_result();
        renegade_metrics::record_match_volume(
            &match_result,
            true, // is_external_match
            &[ctx.wallet_id],
        );
    }

    /// Record the internal fill and update the order metadata
    pub(crate) async fn record_order_fill(
        &self,
        order_id: OrderIdentifier,
        ctx: &PostSettlementCtx<'_>,
    ) -> Result<(), OnChainEventListenerError> {
        let match_result = ctx.external_match_result.to_match_result();
        // Get the order metadata
        let mut metadata = self
            .state()
            .get_order_metadata(&order_id)
            .await?
            .ok_or(OnChainEventListenerError::State(ERR_NO_ORDER_METADATA.to_string()))?;

        // Increment filled amount and transition state if the entire order has matched
        metadata.record_partial_fill(match_result.base_amount, ctx.price);
        if metadata.data.amount == metadata.total_filled() {
            metadata.state = OrderState::Filled;
        }

        self.state().update_order_metadata(metadata).await?;
        Ok(())
    }

    /// Emit `ExternalFill` relayer event
    pub(crate) fn emit_event(
        &self,
        order_id: OrderIdentifier,
        ctx: &PostSettlementCtx<'_>,
    ) -> Result<(), OnChainEventListenerError> {
        use job_types::event_manager::{ExternalFillEvent, RelayerEventType, try_send_event};

        let fee_take = internal_fee_take(ctx.external_match_result);
        let event = RelayerEventType::ExternalFill(ExternalFillEvent::new(
            ctx.wallet_id,
            order_id,
            ctx.price,
            ctx.external_match_result.clone(),
            fee_take,
        ));
        let queue = &self.config.event_queue;
        try_send_event(event, queue)
            .map_err(|e| OnChainEventListenerError::SendMessage(e.to_string()))
    }
}

// -----------
// | Helpers |
// -----------

/// Compute execution price (quote/base)
fn execution_price(external_match_result: &ExternalMatchResult) -> TimestampedPrice {
    let base = external_match_result.base_amount as f64;
    let quote = external_match_result.quote_amount as f64;
    TimestampedPrice::new(quote / base)
}

/// Compute internal party fee take
fn internal_fee_take(external_match_result: &ExternalMatchResult) -> FeeTake {
    let relayer_fee = FixedPoint::from_f64_round_down(EXTERNAL_MATCH_RELAYER_FEE);
    let protocol_fee = get_external_match_fee(&external_match_result.base_mint);
    let side = external_match_result.internal_party_side();
    compute_fee_obligation_with_protocol_fee(
        relayer_fee,
        protocol_fee,
        side,
        &external_match_result.to_match_result(),
    )
}
