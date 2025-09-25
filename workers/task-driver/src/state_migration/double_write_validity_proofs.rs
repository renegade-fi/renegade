//! Copy over validity proofs from the network order structs into the new table

use common::types::network_order::NetworkOrder;
use state::State;
use tracing::error;

/// Copy over validity proofs from the network order structs into the new table
pub async fn double_write_validity_proofs(state: &State) -> Result<(), String> {
    let all_orders = state.get_all_orders().await?;
    for order in all_orders {
        let oid = order.id;
        if let Err(e) = copy_validity_proofs(order, state).await {
            error!("failed to copy validity proofs for order {oid}: {e}");
        }
    }

    Ok(())
}

/// Copy the validity proofs from a network order into the new table
async fn copy_validity_proofs(order: NetworkOrder, state: &State) -> Result<(), String> {
    // We start a new write tx for each order to avoid holding the DB write lock
    // for the duration of the migration
    state
        .with_write_tx(move |tx| {
            // Write the validity proof witness
            if let Some(w) = order.validity_proof_witnesses {
                tx.write_validity_proof_witness(&order.id, &w)?;
            }

            Ok(())
        })
        .await?;

    Ok(())
}
