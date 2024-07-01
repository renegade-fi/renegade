//! Applicator methods for the wallet index, separated out for discoverability

use common::types::{
    network_order::NetworkOrder,
    wallet::{
        order_metadata::{OrderMetadata, OrderState},
        Wallet,
    },
};
use external_api::bus_message::{wallet_topic, SystemBusMessage};
use itertools::Itertools;
use libmdbx::RW;

use crate::storage::tx::StateTxn;

use super::{
    error::StateApplicatorError, return_type::ApplicatorReturnType, Result, StateApplicator,
};

/// Error message emitted when metadata for an order is not found
const ERR_NO_METADATA: &str = "metadata not found for order";

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add a locally managed wallet to the wallet index
    ///
    /// This may happen, for example, when a new wallet is created by
    /// a user on one cluster node, and the others must replicate it
    pub fn add_wallet(&self, wallet: &Wallet) -> Result<ApplicatorReturnType> {
        // Add the wallet to the wallet indices
        let tx = self.db().new_write_tx()?;
        tx.write_wallet(wallet)?;
        tx.commit()?;

        // Publish a message to the bus describing the wallet update
        let wallet_topic = wallet_topic(&wallet.wallet_id);
        self.system_bus().publish(
            wallet_topic,
            SystemBusMessage::WalletUpdate { wallet: Box::new(wallet.clone().into()) },
        );

        Ok(ApplicatorReturnType::None)
    }

    /// Update a wallet in the state
    ///
    /// This update may take many forms: placing/cancelling an order, depositing
    /// or withdrawing a balance, etc.
    ///
    /// It is assumed that the update to the wallet is proven valid and posted
    /// on-chain before this method is called. That is, we maintain the
    /// invariant that the state stored by this module is valid -- but
    /// possibly stale -- contract state
    pub fn update_wallet(&self, wallet: &Wallet) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;

        // Index the orders in the wallet
        self.index_orders_with_tx(wallet, &tx)?;

        // Update the order -> wallet mapping and index the wallet
        tx.write_wallet(wallet)?;
        tx.commit()?;

        // Push an update to the bus
        let wallet_topic = wallet_topic(&wallet.wallet_id);
        self.system_bus().publish(
            wallet_topic,
            SystemBusMessage::WalletUpdate { wallet: Box::new(wallet.clone().into()) },
        );

        Ok(ApplicatorReturnType::None)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Index the orders of a wallet and update denormalized order state
    fn index_orders_with_tx(&self, wallet: &Wallet, tx: &StateTxn<RW>) -> Result<()> {
        // Add network orders for the locally managed wallet
        self.add_network_orders(wallet, tx)?;

        // Update the order -> wallet mapping
        let nonzero_orders = wallet.get_nonzero_orders().into_keys().collect_vec();
        tx.index_orders(&wallet.wallet_id, &nonzero_orders)?;

        // Handle new orders and previous orders that are not cancelled
        self.handle_new_and_cancelled_orders(wallet, tx)?;

        // Change the state of each active order in the wallet to `Created`
        // to reflect that validity proofs have not been created yet
        let wallet_id = wallet.wallet_id;
        for id in wallet.get_nonzero_orders().into_keys() {
            let mut md = tx
                .get_order_metadata(wallet_id, id)?
                .ok_or(StateApplicatorError::MissingEntry(ERR_NO_METADATA))?;
            md.state = OrderState::Created;
            self.update_order_metadata_with_tx(md, tx)?;
        }

        Ok(())
    }

    /// Add network order entries for the non-zero orders in the wallet
    fn add_network_orders(&self, wallet: &Wallet, tx: &StateTxn<RW>) -> Result<()> {
        let nullifier = wallet.get_wallet_nullifier();
        for id in wallet.get_nonzero_orders().into_keys() {
            let net_order = NetworkOrder::new(
                id,
                nullifier,
                self.config.cluster_id.clone(),
                true, // local
            );

            // Update the order priority, the order, and its nullifier
            tx.mark_order_local(&id)?;
            tx.write_order_priority(&net_order)?;
            tx.write_order(&net_order)?;
        }

        Ok(())
    }

    /// Update order metadata states for cancellations and additions
    fn handle_new_and_cancelled_orders(&self, wallet: &Wallet, tx: &StateTxn<RW>) -> Result<()> {
        let old_wallet = tx.get_wallet(&wallet.wallet_id)?;
        let old_orders = old_wallet
            .map(|w| w.get_nonzero_orders().into_keys().collect_vec())
            .unwrap_or_default();

        // New orders
        let wallet_id = wallet.wallet_id;
        for (id, o) in wallet.get_nonzero_orders() {
            if !old_orders.contains(&id) {
                let new_state = OrderMetadata::new(id, o);
                self.update_order_metadata_with_tx(new_state, tx)?;
                // TODO: Add the order to the global matching pool
            }
        }

        // Cancelled orders
        for id in old_orders {
            if !wallet.contains_order(&id) {
                let mut old_meta = tx
                    .get_order_metadata(wallet_id, id)?
                    .ok_or(StateApplicatorError::MissingEntry(ERR_NO_METADATA))?;

                // Only update the state if it has not already entered a terminal state
                if !old_meta.state.is_terminal() {
                    old_meta.state = OrderState::Cancelled;
                    self.update_order_metadata_with_tx(old_meta, tx)?;
                    // TODO: Remove the order from its matching pool
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "all-tests"))]
pub(crate) mod test {
    use common::types::{
        wallet::Wallet,
        wallet_mocks::{mock_empty_wallet, mock_order},
    };
    use uuid::Uuid;

    use crate::{applicator::test_helpers::mock_applicator, ORDER_TO_WALLET_TABLE, WALLETS_TABLE};

    // -----------
    // | Helpers |
    // -----------

    /// Tests adding a new wallet to the index
    #[test]
    fn test_add_wallet() {
        let applicator = mock_applicator();

        // Add a wallet and an order to the wallet
        let wallet = mock_empty_wallet();
        applicator.add_wallet(&wallet).unwrap();

        // Check that the wallet is indexed correctly
        let expected_wallet: Wallet = wallet;

        let db = applicator.db();
        let wallet: Wallet = db.read(WALLETS_TABLE, &expected_wallet.wallet_id).unwrap().unwrap();

        assert_eq!(wallet, expected_wallet);
    }

    /// Test updating the wallet
    #[test]
    fn test_update_wallet() {
        let applicator = mock_applicator();

        // Add a wallet
        let mut wallet = mock_empty_wallet();
        applicator.add_wallet(&wallet).unwrap();

        // Update the wallet by adding an order
        wallet.orders.insert(Uuid::new_v4(), mock_order());
        applicator.update_wallet(&wallet).unwrap();

        // Check that the indexed wallet is as expected
        let expected_wallet: Wallet = wallet.clone();
        let db = applicator.db();
        let wallet: Wallet = db.read(WALLETS_TABLE, &expected_wallet.wallet_id).unwrap().unwrap();

        assert_eq!(wallet, expected_wallet);

        // Check the order -> wallet mapping
        let order_id = wallet.orders.keys().next().unwrap();
        let wallet_id: Uuid = db.read(ORDER_TO_WALLET_TABLE, order_id).unwrap().unwrap();
        assert_eq!(wallet_id, expected_wallet.wallet_id);
    }
}
