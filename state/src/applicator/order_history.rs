//! Applicator handlers for order metadata updates

use crate::storage::tx::StateTxn;

use super::{StateApplicator, error::StateApplicatorError, return_type::ApplicatorReturnType};
use common::types::wallet::order_metadata::OrderMetadata;
use common::types::wallet::{OrderIdentifier, WalletIdentifier};
use external_api::bus_message::{SystemBusMessage, wallet_order_history_topic};
use libmdbx::RW;
use tracing::warn;

/// Error emitted when a wallet cannot be found for an order
const ERR_MISSING_WALLET: &str = "wallet not found";

impl StateApplicator {
    /// Handle an update to an order's metadata
    pub fn update_order_metadata(
        &self,
        meta: OrderMetadata,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        // Update the state
        let tx = self.db().new_write_tx()?;
        self.update_order_metadata_with_tx(meta, &tx)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }

    /// Update the state of an order's metadata given a transaction
    pub(crate) fn update_order_metadata_with_tx(
        &self,
        meta: OrderMetadata,
        tx: &StateTxn<RW>,
    ) -> Result<(), StateApplicatorError> {
        let wallet = tx
            .get_wallet_id_for_order(&meta.id)?
            .ok_or(StateApplicatorError::MissingEntry(ERR_MISSING_WALLET))?;

        let old_meta = tx.get_order_metadata(wallet, meta.id)?;
        match old_meta {
            // Add the order to the history if it doesn't exist
            None => tx.push_order_history(&wallet, meta.clone())?,
            Some(old_meta) => {
                let became_terminal = !old_meta.state.is_terminal() && meta.state.is_terminal();

                // Always write the metadata update — even for terminal orders
                // when history is disabled. This keeps the Filled/Cancelled
                // state visible so that concurrent tasks see `is_terminal()`
                // and skip the order cleanly. Pruning is deferred to
                // `PruneTerminalOrderMetadata` after the wallet refresh.
                tx.update_order_metadata(&wallet, meta.clone())?;

                if became_terminal {
                    // Remove the order from the set of local open
                    // orders as it is no longer matchable
                    tx.remove_local_order(&meta.id)?;
                }
            },
        }

        // Write to system bus
        let topic = wallet_order_history_topic(&wallet);
        self.system_bus().publish(topic, SystemBusMessage::OrderMetadataUpdated { order: meta });

        Ok(())
    }

    /// Remove terminal order metadata (deferred prune).
    ///
    /// Called by the wallet refresh task after `update_wallet` has made the
    /// wallet consistent. Only prunes if the metadata exists and is terminal
    /// and historical state recording is disabled.
    pub fn prune_terminal_order_metadata(
        &self,
        wallet_id: WalletIdentifier,
        order_id: OrderIdentifier,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        let order_history_enabled = tx.get_historical_state_enabled()?;

        if order_history_enabled {
            return Ok(ApplicatorReturnType::None);
        }

        let meta = tx.get_order_metadata(wallet_id, order_id)?;
        match meta {
            Some(m) if m.state.is_terminal() => {
                tx.remove_order_from_history(&wallet_id, &order_id)?;
                tx.commit()?;
            },
            Some(_) => {
                warn!(
                    "prune_terminal_order_metadata called for non-terminal order {order_id}, skipping"
                );
            },
            None => {
                // Already pruned or never existed — no-op
            },
        }

        Ok(ApplicatorReturnType::None)
    }
}

#[cfg(test)]
mod tests {
    use common::types::{
        price::TimestampedPrice, wallet::order_metadata::OrderState, wallet_mocks::mock_order,
    };
    use uuid::Uuid;

    use crate::applicator::test_helpers::mock_applicator;

    use super::*;

    /// Tests updating an order in the history
    #[test]
    fn test_update_metadata() {
        let applicator = mock_applicator();
        let db = applicator.db();
        let wallet_id = Uuid::new_v4();
        let order_id = Uuid::new_v4();

        // Add initial metadata
        let order = mock_order();
        let mut md = OrderMetadata {
            id: order_id,
            data: order,
            state: OrderState::Created,
            fills: vec![],
            created: 1,
        };
        let tx = db.new_write_tx().unwrap();
        tx.push_order_history(&wallet_id, md.clone()).unwrap();

        // Add an association of wallet to order
        tx.index_orders(&wallet_id, &[order_id]).unwrap();
        tx.commit().unwrap();

        // Modify the metadata and push
        md.record_partial_fill(1, TimestampedPrice::new(2.));
        applicator.update_order_metadata(md).unwrap();

        // Check the state
        let tx = db.new_read_tx().unwrap();
        let md = tx.get_order_metadata(wallet_id, order_id).unwrap().unwrap();
        assert_eq!(md.total_filled(), 1);
    }
}
