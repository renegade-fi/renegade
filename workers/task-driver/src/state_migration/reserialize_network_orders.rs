//! Re-serialize network orders to remove the validity proof witnesses

use common::types::network_order::NetworkOrder;
use state::State;
use tracing::error;

/// Re-serialize network orders to remove the validity proof witnesses
pub async fn reserialize_network_orders(state: &State) -> Result<(), String> {
    let all_orders = state.get_all_orders().await?;
    for order in all_orders {
        let oid = order.id;
        if let Err(e) = write_order(order, state).await {
            error!("error writing through order {oid}: {e}");
        }
    }

    Ok(())
}

/// Write-through an order back to state so that it goes through the new
/// serialization path
async fn write_order(order: NetworkOrder, state: &State) -> Result<(), String> {
    state
        .with_write_tx(move |tx| tx.write_order(&order).map_err(Into::into))
        .await
        .map_err(|e| e.to_string())
}
