//! Applicator methods for the wallet index, separated out for discoverability

use common::types::{
    network_order::NetworkOrder,
    wallet::{OrderIdentifier, Wallet, WalletIdentifier},
};
use external_api::bus_message::{wallet_topic_name, SystemBusMessage};
use itertools::Itertools;
use libmdbx::RW;
use state_proto::{AddWallet as AddWalletMessage, UpdateWallet as UpdateWalletMessage};

use crate::{applicator::error::StateApplicatorError, storage::db::DbTxn};

use super::{Result, StateApplicator, ORDER_TO_WALLET_TABLE, WALLETS_TABLE};

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add a locally managed wallet to the wallet index
    ///
    /// This may happen, for example, when a new wallet is created by
    /// a user on one cluster node, and the others must replicate it
    pub fn add_wallet(&self, msg: AddWalletMessage) -> Result<()> {
        // Parse the wallet from the message
        let wallet: Wallet = msg
            .wallet
            .ok_or_else(|| {
                StateApplicatorError::Parse("AddWalletMessage: missing wallet".to_string())
            })
            .and_then(|w| w.try_into().map_err(StateApplicatorError::Proto))?;

        // Add the wallet to the wallet indices
        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;

        Self::index_orders(
            &wallet.wallet_id,
            &wallet.orders.keys().cloned().collect_vec(),
            &tx,
        )?;
        Self::write_wallet_with_tx(&wallet, &tx)?;

        tx.commit().map_err(StateApplicatorError::Storage)?;

        // Publish a message to the bus describing the wallet update
        let wallet_topic = wallet_topic_name(&wallet.wallet_id);
        self.system_bus().publish(
            wallet_topic,
            SystemBusMessage::WalletUpdate {
                wallet: Box::new(wallet.clone().into()),
            },
        );

        Ok(())
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
    pub fn update_wallet(&self, msg: UpdateWalletMessage) -> Result<()> {
        // Parse the wallet from the message
        let wallet: Wallet = msg
            .wallet
            .ok_or_else(|| {
                StateApplicatorError::Parse("UpdateWalletMessage: missing wallet".to_string())
            })
            .and_then(|w| w.try_into().map_err(StateApplicatorError::Proto))?;

        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;

        // Any new orders in the wallet should be added to the orderbook
        let nullifier = wallet.get_wallet_nullifier();
        for (id, _order) in wallet.orders.iter().filter(|(_id, order)| !order.is_zero()) {
            Self::add_order_with_tx(
                &NetworkOrder::new(
                    *id,
                    nullifier,
                    self.config.cluster_id.clone(),
                    true, // local
                ),
                &tx,
            )?;
        }

        // Update the order -> wallet mapping and index the wallet
        Self::index_orders(
            &wallet.wallet_id,
            &wallet.orders.keys().cloned().collect_vec(),
            &tx,
        )?;
        Self::write_wallet_with_tx(&wallet, &tx)?;

        tx.commit().map_err(StateApplicatorError::Storage)?;

        // Push an update to the bus
        let wallet_topic = wallet_topic_name(&wallet.wallet_id);
        self.system_bus().publish(
            wallet_topic,
            SystemBusMessage::WalletUpdate {
                wallet: Box::new(wallet.clone().into()),
            },
        );

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Update the order-to-wallet mapping for each order in the given list
    fn index_orders(
        wallet_id: &WalletIdentifier,
        orders: &[OrderIdentifier],
        tx: &DbTxn<'_, RW>,
    ) -> Result<()> {
        for order in orders.iter() {
            tx.write(ORDER_TO_WALLET_TABLE, order, wallet_id)
                .map_err(StateApplicatorError::Storage)?;
        }

        Ok(())
    }

    /// Write a given wallet to storage
    fn write_wallet_with_tx(wallet: &Wallet, tx: &DbTxn<'_, RW>) -> Result<()> {
        tx.write(WALLETS_TABLE, &wallet.wallet_id, wallet)
            .map_err(StateApplicatorError::Storage)
    }
}

#[cfg(all(test, feature = "all-tests"))]
pub(crate) mod test {
    use common::types::{wallet::Wallet, wallet_mocks::mock_empty_wallet};
    use constants::MERKLE_HEIGHT;
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use state_proto::{
        AddWallet, AddWalletBuilder, KeyChain as ProtoKeyChain, KeyChainBuilder,
        Order as ProtoOrder, OrderBuilder, OrderSide, PrivateKeyChainBuilder,
        PublicKeyChainBuilder, UpdateWalletBuilder, Wallet as ProtoWallet,
        WalletAuthenticationPathBuilder, WalletBuilder,
    };
    use uuid::Uuid;

    use crate::applicator::{test_helpers::mock_applicator, ORDER_TO_WALLET_TABLE, WALLETS_TABLE};

    // -----------
    // | Helpers |
    // -----------

    /// Create a mock keychain
    fn dummy_proto_keychain() -> ProtoKeyChain {
        let mock_wallet = mock_empty_wallet();
        let public_keys = &mock_wallet.key_chain.public_keys;
        let secret_keys = &mock_wallet.key_chain.secret_keys;

        let pk_root_bytes = serde_json::to_vec(&public_keys.pk_root).unwrap();

        KeyChainBuilder::default()
            .public_keys(
                PublicKeyChainBuilder::default()
                    .pk_match(public_keys.pk_match.key.into())
                    .pk_root(pk_root_bytes)
                    .build()
                    .unwrap(),
            )
            .secret_keys(
                PrivateKeyChainBuilder::default()
                    .sk_match(secret_keys.sk_match.key.into())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    /// Create a dummy order
    fn dummy_proto_order() -> ProtoOrder {
        OrderBuilder::default()
            .id(Uuid::new_v4().into())
            .quote_mint(BigUint::from(1u8).into())
            .base_mint(BigUint::from(2u8).into())
            .side(OrderSide::Buy.into())
            .amount(10)
            .worst_case_price(10.)
            .timestamp(0)
            .build()
            .unwrap()
    }

    /// Create a dummy proto wallet
    fn dummy_proto_wallet() -> ProtoWallet {
        let mut rng = thread_rng();
        let opening = WalletAuthenticationPathBuilder::default()
            .leaf_index(0)
            .value(Scalar::random(&mut rng).into())
            .path_siblings(
                (0..MERKLE_HEIGHT)
                    .map(|_| Scalar::random(&mut rng).into())
                    .collect(),
            )
            .build()
            .unwrap();

        // Add a single order to allowing us to test order -> wallet indexing
        WalletBuilder::default()
            .id(Uuid::new_v4().into())
            .orders(vec![dummy_proto_order()])
            .keychain(dummy_proto_keychain())
            .opening(opening)
            .blinder(Scalar::random(&mut rng).into())
            .build()
            .unwrap()
    }

    /// Create a dummy `AddWallet` message
    pub(crate) fn dummy_add_wallet() -> AddWallet {
        let wallet = dummy_proto_wallet();
        AddWalletBuilder::default().wallet(wallet).build().unwrap()
    }

    /// Tests adding a new wallet to the index
    #[test]
    fn test_add_wallet() {
        let applicator = mock_applicator();

        // Add a wallet
        let msg = dummy_add_wallet();
        applicator.add_wallet(msg.clone()).unwrap();

        // Check that the wallet is indexed correctly
        let expected_wallet: Wallet = msg.wallet.unwrap().try_into().unwrap();

        let db = applicator.db();
        let wallet: Wallet = db
            .read(WALLETS_TABLE, &expected_wallet.wallet_id)
            .unwrap()
            .unwrap();

        assert_eq!(wallet, expected_wallet);

        // Check that the order -> wallet mapping is correct
        let order_id = expected_wallet.orders.keys().next().unwrap();
        let wallet_id: Uuid = db.read(ORDER_TO_WALLET_TABLE, order_id).unwrap().unwrap();

        assert_eq!(wallet_id, expected_wallet.wallet_id);
    }

    /// Test updating the wallet
    #[test]
    fn test_update_wallet() {
        let applicator = mock_applicator();

        // Add a wallet
        let msg = dummy_add_wallet();
        applicator.add_wallet(msg.clone()).unwrap();

        // Update the wallet by removing the orders
        let mut wallet = msg.wallet.unwrap();
        wallet.orders = vec![];
        let new_msg = UpdateWalletBuilder::default()
            .wallet(wallet.clone())
            .build()
            .unwrap();
        applicator.update_wallet(new_msg).unwrap();

        // Check that the indexed wallet is as expected
        let expected_wallet: Wallet = wallet.try_into().unwrap();
        let db = applicator.db();
        let wallet: Wallet = db
            .read(WALLETS_TABLE, &expected_wallet.wallet_id)
            .unwrap()
            .unwrap();

        assert_eq!(wallet, expected_wallet);
    }
}
