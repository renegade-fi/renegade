//! Applicator handlers for order metadata updates

use crate::order_metadata::ERR_MISSING_WALLET;

use super::{error::StateApplicatorError, StateApplicator};
use common::types::wallet::order_metadata::OrderMetadata;
use external_api::bus_message::{wallet_order_history_topic, SystemBusMessage};

impl StateApplicator {
    /// Handle an update to an order's metadata
    pub fn update_order_metadata(&self, meta: OrderMetadata) -> Result<(), StateApplicatorError> {
        // Update the state
        let tx = self.db().new_write_tx()?;
        let wallet = tx
            .get_wallet_for_order(&meta.id)?
            .ok_or(StateApplicatorError::MissingEntry(ERR_MISSING_WALLET))?;
        tx.update_order_metadata(&wallet, meta)?;

        tx.commit()?;

        // Write to system bus
        let topic = wallet_order_history_topic(&wallet);
        self.system_bus().publish(topic, SystemBusMessage::OrderMetadataUpdated { order: meta });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use common::types::wallet::order_metadata::OrderState;
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
        let mut md =
            OrderMetadata { id: order_id, state: OrderState::Created, filled: 0, created: 1 };
        let tx = db.new_write_tx().unwrap();
        tx.push_order_history(&wallet_id, md).unwrap();

        // Add an association of wallet to order
        tx.index_orders(&wallet_id, &[order_id]).unwrap();
        tx.commit().unwrap();

        // Modify the metadata and push
        md.filled += 1;
        applicator.update_order_metadata(md).unwrap();

        // Check the state
        let tx = db.new_read_tx().unwrap();
        let md = tx.get_order_metadata(wallet_id, order_id).unwrap().unwrap();
        assert_eq!(md.filled, 1);
    }
}
