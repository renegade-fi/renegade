//! Helpers for transitioning order states and recording them in order history

use circuit_types::{fixed_point::FixedPoint, r#match::MatchResult};
use common::types::wallet::{order_metadata::OrderState, OrderIdentifier};
use state::State;

/// The error message emitted when metadata for an order cannot be found
const ERR_NO_ORDER_METADATA: &str = "order metadata not found";

/// Update an order's state to `SettlingMatch`
pub async fn transition_order_settling(
    order_id: OrderIdentifier,
    state: &State,
) -> Result<(), String> {
    let mut metadata =
        state.get_order_metadata(&order_id).await?.ok_or(ERR_NO_ORDER_METADATA.to_string())?;
    metadata.state = OrderState::SettlingMatch;
    state.update_order_metadata(metadata).await?;

    Ok(())
}

/// Record the result of a match in the order's metadata
pub async fn record_order_fill(
    order_id: OrderIdentifier,
    match_res: &MatchResult,
    price: FixedPoint,
    state: &State,
) -> Result<(), String> {
    // Get the order metadata
    let mut metadata =
        state.get_order_metadata(&order_id).await?.ok_or(ERR_NO_ORDER_METADATA.to_string())?;

    // Increment filled amount and transition state if the entire order has matched
    metadata.record_partial_fill(match_res.base_amount, price);
    if metadata.data.amount == metadata.total_filled() {
        metadata.state = OrderState::Filled;
    }

    state.update_order_metadata(metadata).await?;
    Ok(())
}
