//! Debug migration to dump wallet and order metadata state
//!
//! Collects raw data about wallet orders and their metadata for analysis.

use std::collections::{HashMap, HashSet};

use common::types::wallet::{OrderIdentifier, WalletIdentifier};
use state::State;
use tracing::info;

/// The wallet IDs to inspect
/// - ec7f8aea: wallet with repeatedly failing refresh tasks
/// - 3067c475: counterparty in the failing settle-match
const WALLET_IDS: &[&str] =
    &["ec7f8aea-3b3e-4edf-6ee3-b3332beb5497", "3067c475-82ac-675b-bc10-73d7cc00cc60"];

/// Tag for filtering in Datadog: @debug:"metadata-investigation"
const DEBUG_TAG: &str = "metadata-investigation";
/// Limit the number of history-only entries to log
const HISTORY_ONLY_LOG_LIMIT: usize = 50;

/// Dump wallet and order metadata state for analysis
pub async fn debug_order_metadata(state: &State) -> Result<(), String> {
    for wallet_id_str in WALLET_IDS {
        inspect_wallet(wallet_id_str, state).await?;
    }
    Ok(())
}

/// Inspect a single wallet for order metadata issues
async fn inspect_wallet(wallet_id_str: &str, state: &State) -> Result<(), String> {
    let wallet_id = wallet_id_str.parse::<WalletIdentifier>().map_err(|e| e.to_string())?;

    info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "=== DEBUG: wallet ===");

    // Get wallet
    let Some(wallet) = state.get_wallet(&wallet_id).await? else {
        info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "WALLET: not found");
        return Ok(());
    };

    let nonzero_order_ids: Vec<OrderIdentifier> = wallet.get_nonzero_orders().into_keys().collect();
    let wallet_order_ids: HashSet<OrderIdentifier> = wallet.orders.keys().copied().collect();

    info!(
        debug = DEBUG_TAG,
        wallet_id = %wallet_id,
        order_slots = wallet.orders.len(),
        nonzero_orders = nonzero_order_ids.len(),
        "WALLET: found"
    );

    // Dump all orders in wallet
    info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "--- ORDERS IN WALLET ---");
    for (order_id, order) in wallet.orders.iter() {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %order_id,
            amount = order.amount,
            side = ?order.side,
            is_zero = order.is_zero(),
            "ORDER"
        );
    }

    // Fetch order history and order->wallet index in a single read tx
    let (history, order_to_wallet) = state
        .with_read_tx({
            let wallet_id = wallet_id;
            let nonzero_order_ids = nonzero_order_ids.clone();
            move |tx| {
                let history = tx.get_order_history(&wallet_id)?;
                let mut order_to_wallet = HashMap::new();
                for order_id in nonzero_order_ids {
                    let indexed_wallet = tx.get_wallet_id_for_order(&order_id)?;
                    order_to_wallet.insert(order_id, indexed_wallet);
                }

                Ok((history, order_to_wallet))
            }
        })
        .await
        .map_err(|e| e.to_string())?;

    let history_map: HashMap<OrderIdentifier, _> =
        history.iter().map(|meta| (meta.id, meta)).collect();

    // Dump order metadata and index state for nonzero orders
    info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "--- ORDER INDEX + METADATA (nonzero) ---");
    let mut missing_metadata = Vec::new();
    let mut missing_index = Vec::new();
    let mut index_mismatch = Vec::new();
    for order_id in &nonzero_order_ids {
        let indexed_wallet = order_to_wallet.get(order_id).copied().flatten();
        let metadata = history_map.get(order_id).copied();

        if metadata.is_none() {
            missing_metadata.push(*order_id);
        }

        match indexed_wallet {
            Some(id) if id != wallet_id => index_mismatch.push((*order_id, id)),
            None => missing_index.push(*order_id),
            _ => {},
        }

        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %order_id,
            indexed_wallet = ?indexed_wallet,
            metadata_present = metadata.is_some(),
            metadata_state = ?metadata.map(|m| &m.state),
            metadata_amount = ?metadata.map(|m| &m.data.amount),
            metadata_filled = ?metadata.map(|m| m.total_filled()),
            metadata_fills_count = ?metadata.map(|m| m.fills.len()),
            "ORDER_CHECK"
        );
    }

    info!(
        debug = DEBUG_TAG,
        wallet_id = %wallet_id,
        missing_metadata = missing_metadata.len(),
        missing_index = missing_index.len(),
        index_mismatch = index_mismatch.len(),
        "ORDER_CHECK_SUMMARY"
    );

    for order_id in missing_metadata {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %order_id,
            "MISSING_METADATA"
        );
    }

    for order_id in missing_index {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %order_id,
            "MISSING_ORDER_INDEX"
        );
    }

    for (order_id, indexed_wallet) in index_mismatch {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %order_id,
            indexed_wallet = %indexed_wallet,
            "ORDER_INDEX_MISMATCH"
        );
    }

    // Identify metadata entries that are not present in the wallet
    let history_only =
        history.iter().filter(|meta| !wallet_order_ids.contains(&meta.id)).collect::<Vec<_>>();
    info!(
        debug = DEBUG_TAG,
        wallet_id = %wallet_id,
        history_entries = history.len(),
        history_only = history_only.len(),
        "HISTORY_SUMMARY"
    );

    info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "--- HISTORY ONLY (not in wallet) ---");
    for meta in history_only.iter().take(HISTORY_ONLY_LOG_LIMIT) {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            order_id = %meta.id,
            state = ?meta.state,
            amount = meta.data.amount,
            filled = meta.total_filled(),
            "HISTORY_ONLY_ENTRY"
        );
    }

    if history_only.len() > HISTORY_ONLY_LOG_LIMIT {
        info!(
            debug = DEBUG_TAG,
            wallet_id = %wallet_id,
            skipped = history_only.len() - HISTORY_ONLY_LOG_LIMIT,
            "HISTORY_ONLY_TRUNCATED"
        );
    }

    info!(debug = DEBUG_TAG, wallet_id = %wallet_id, "=== END DEBUG ===");
    Ok(())
}
