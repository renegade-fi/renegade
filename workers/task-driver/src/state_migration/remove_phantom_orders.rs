//! Removes orders that are no longer part of any wallet
//!
//! This checks both the order book table and the local orders list

use common::types::wallet::OrderIdentifier;
use state::State;
use tracing::{error, info};

/// Remove all orders that are no longer part of a wallet
pub async fn remove_phantom_orders(state: &State) -> Result<(), String> {
    // Remove all phantom orders in the orders table
    let phantom_orders = find_phantom_orders(state).await?;
    info!("removing {} phantom orders...", phantom_orders.len());
    remove_orders_from_order_book(state, &phantom_orders).await?;

    // Remove all local orders that are not part of a wallet
    let missing_local_orders = find_missing_local_orders(state).await?;
    info!("removing {} missing local orders...", missing_local_orders.len());
    remove_local_orders(state, &missing_local_orders).await?;

    Ok(())
}

// --- Find Orders --- //

/// Find all phantom orders
async fn find_phantom_orders(state: &State) -> Result<Vec<OrderIdentifier>, String> {
    let all_orders = state.get_all_orders().await?;
    let mut phantom_orders = Vec::new();
    for order in all_orders {
        let order_id = order.id;
        if check_order_missing(state, &order_id).await? {
            phantom_orders.push(order_id);
        }
    }

    Ok(phantom_orders)
}

/// Find all local orders that are not part of a wallet
async fn find_missing_local_orders(state: &State) -> Result<Vec<OrderIdentifier>, String> {
    let local_orders = state
        .with_read_tx(|tx| {
            let orders = tx.get_local_orders()?;
            Ok(orders)
        })
        .await?;

    let mut missing_local_orders = Vec::new();
    for order_id in local_orders {
        if check_order_missing(state, &order_id).await? {
            missing_local_orders.push(order_id);
        }
    }

    Ok(missing_local_orders)
}

/// Check whether an order is missing from its wallet
async fn check_order_missing(state: &State, order_id: &OrderIdentifier) -> Result<bool, String> {
    // Check that the order has a wallet ID mapped to it
    let maybe_wallet = state.get_wallet_for_order(order_id).await?;
    if maybe_wallet.is_none() || !maybe_wallet.unwrap().contains_order(order_id) {
        return Ok(true);
    }

    Ok(false)
}

// --- Remove Orders --- //

/// Remove a set of orders from the order book state
async fn remove_orders_from_order_book(
    state: &State,
    orders: &[OrderIdentifier],
) -> Result<(), String> {
    // Remove each order in a new tx to avoid blocking the db for too long
    for order_id in orders {
        let oid = *order_id;
        let res = state
            .with_write_tx(move |tx| {
                tx.delete_order(&oid)?;
                Ok(())
            })
            .await;

        // Do not abort on error, just log them
        if let Err(e) = res {
            error!("error removing order {order_id}: {e}");
        }
    }

    Ok(())
}

/// Remove a set of orders from the local orders list
async fn remove_local_orders(state: &State, order_ids: &[OrderIdentifier]) -> Result<(), String> {
    for order_id in order_ids {
        let oid = *order_id;
        let res = state
            .with_write_tx(move |tx| {
                tx.remove_local_order(&oid)?;
                Ok(())
            })
            .await;

        // Do not abort on error, just log them
        if let Err(e) = res {
            error!("error removing local order {order_id}: {e}");
        }
    }

    Ok(())
}
