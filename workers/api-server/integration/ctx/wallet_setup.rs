//! Setup wallets for an order

use std::sync::Arc;

use circuit_types::{
    balance::Balance, fixed_point::FixedPoint, max_amount, max_price, order::OrderSide, Amount,
};
use common::types::{
    proof_bundles::mocks::{dummy_validity_proof_bundle, dummy_validity_witness_bundle},
    wallet::{Order, OrderIdentifier, Wallet},
    wallet_mocks::mock_empty_wallet,
};
use external_api::http::external_match::ExternalOrder;
use eyre::Result;

use crate::ctx::IntegrationTestCtx;
use crate::to_eyre::WrapEyre;

impl IntegrationTestCtx {
    /// Setup a wallet with a balance capitalized to match against the given
    /// order
    pub async fn setup_crossing_wallet(&self, order: &ExternalOrder) -> Result<Wallet> {
        // Add a matching order to the wallet
        let matching_order = self.build_matching_order(order)?;
        self.setup_wallet_with_order(matching_order).await
    }

    /// Setup a well capitalized wallet with the given order
    pub async fn setup_wallet_with_order(&self, order: Order) -> Result<Wallet> {
        let mut wallet = mock_empty_wallet();
        let oid = OrderIdentifier::new_v4();
        wallet.add_order(oid, order.clone()).to_eyre()?;

        // Add a balance to capitalize the order
        let balance = self.build_capitalizing_balance(&order);
        wallet.add_balance(balance).to_eyre()?;

        // Add the wallet to the state
        let waiter = self.mock_node.state().update_wallet(wallet.clone()).await?;
        waiter.await.to_eyre()?;

        // Add a validity proof bundle to the state for the order
        self.add_validity_proof_bundle(oid, order).await?;
        Ok(wallet)
    }

    /// Build an order to cross with the given order
    pub fn build_matching_order(&self, order: &ExternalOrder) -> Result<Order> {
        let amount = max_amount(); // Place a max amount order
        self.build_matching_order_with_amount(order, amount)
    }

    /// Build a matching order with the given amount
    pub fn build_matching_order_with_amount(
        &self,
        order: &ExternalOrder,
        amount: Amount,
    ) -> Result<Order> {
        let matching_side = order.side.opposite();
        let worst_case_price = match matching_side {
            OrderSide::Buy => max_price(),
            OrderSide::Sell => FixedPoint::zero(),
        };

        Order::new(
            order.quote_mint.clone(),
            order.base_mint.clone(),
            matching_side,
            amount,
            worst_case_price,
            0,    // min_fill_size
            true, // allow_external_matches
        )
        .to_eyre()
    }

    /// Build a capitalizing balance for the given order
    fn build_capitalizing_balance(&self, order: &Order) -> Balance {
        let mint = order.send_mint().clone();
        let amount = max_amount();
        Balance::new_from_mint_and_amount(mint, amount)
    }

    /// Add a validity proof bundle to the state for the given order
    async fn add_validity_proof_bundle(
        &self,
        order_id: OrderIdentifier,
        order: Order,
    ) -> Result<()> {
        let bundle = dummy_validity_proof_bundle();
        let mut witness = dummy_validity_witness_bundle();
        Arc::make_mut(&mut witness.commitment_witness).order = order.into();
        let waiter = self
            .mock_node
            .state()
            .add_local_order_validity_bundle(order_id, bundle, witness)
            .await?;
        waiter.await.to_eyre()?;

        Ok(())
    }
}
