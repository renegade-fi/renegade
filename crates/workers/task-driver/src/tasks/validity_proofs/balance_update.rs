//! Helpers for refreshing validity proofs after balance updates.

use alloy::primitives::Address;
use circuit_types::schnorr::SchnorrSignature;
use types_account::{OrderId, order_auth::OrderAuth};
use types_core::AccountId;

use crate::{
    tasks::validity_proofs::{
        error::ValidityProofsError, intent_and_balance::update_intent_and_balance_validity_proof,
        output_balance::update_output_balance_validity_proof,
    },
    traits::TaskContext,
};

/// Refresh Ring 2/3 validity proofs affected by an updated balance mint.
///
/// When a darkpool balance changes, any private order using this mint as input
/// may require an `INTENT AND BALANCE VALIDITY` update, and any private order
/// using this mint as output may require an `OUTPUT BALANCE VALIDITY` update.
pub async fn refresh_validity_proofs_for_updated_balance(
    account_id: AccountId,
    mint: Address,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let output_order_ids = ctx.state.get_orders_with_output_token(&account_id, &mint).await?;
    refresh_output_balance_validity_for_orders(account_id, &output_order_ids, ctx).await?;

    let input_order_ids = ctx.state.get_orders_with_input_token(&account_id, &mint).await?;
    refresh_intent_and_balance_validity_for_orders(account_id, &input_order_ids, ctx).await?;

    Ok(())
}

/// Refresh output-balance validity proofs for the given orders.
async fn refresh_output_balance_validity_for_orders(
    account_id: AccountId,
    order_ids: &[OrderId],
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    for order_id in order_ids {
        let Some((_, balance_sig)) = get_private_fill_auth(*order_id, ctx).await? else {
            continue;
        };

        update_output_balance_validity_proof(
            account_id,
            *order_id,
            balance_sig,
            true, // force: balance updates should refresh output-balance proofs
            ctx,
        )
        .await?;
    }

    Ok(())
}

/// Refresh intent-and-balance validity proofs for the given orders.
async fn refresh_intent_and_balance_validity_for_orders(
    account_id: AccountId,
    order_ids: &[OrderId],
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    for order_id in order_ids {
        // Fetch private fill auth, this will naturally filter out orders in rings 0/1
        let Some((intent_sig, _)) = get_private_fill_auth(*order_id, ctx).await? else {
            continue;
        };

        update_intent_and_balance_validity_proof(account_id, *order_id, intent_sig, ctx).await?;
    }

    Ok(())
}

/// Fetch renegade-settled auth, returning `None` for non-private-fill orders.
///
/// Returns a tuple containing the intent signature and the new output balance
/// signature.
async fn get_private_fill_auth(
    order_id: OrderId,
    ctx: &TaskContext,
) -> Result<Option<(SchnorrSignature, SchnorrSignature)>, ValidityProofsError> {
    let order_auth =
        ctx.state.get_order_auth(&order_id).await?.ok_or(ValidityProofsError::state(format!(
            "order auth not found for order {order_id}"
        )))?;

    match order_auth {
        OrderAuth::RenegadeSettledOrder { intent_signature, new_output_balance_signature } => {
            Ok(Some((intent_signature, new_output_balance_signature)))
        },
        _ => Ok(None),
    }
}
