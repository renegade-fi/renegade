//! Settlement helpers

use alloy::{
    primitives::Address, rpc::types::TransactionReceipt, signers::local::PrivateKeySigner,
};
use circuit_types::fixed_point::FixedPoint;
use darkpool_types::settlement_obligation::SettlementObligation;
use renegade_solidity_abi::v2::IDarkpoolV2::{FeeRate, PublicIntentPermit, SignatureWithNonce};
use types_account::{
    OrderId,
    balance::{Balance, BalanceLocation},
    order::{Order, PrivacyRing},
};
use types_core::{AccountId, Token};

use crate::{tasks::settlement::helpers::error::SettlementError, traits::TaskContext};

pub mod error;
pub mod obligation_bundle;
pub mod ring0;
pub mod ring1;
pub mod settlement_bundle;

/// A macro that branches between two parties in a settlement
///
/// This is useful for pulling fields conditionally on the party ID.
macro_rules! branch_party {
    ($party_id:expr, $expr0:expr, $expr1:expr) => {
        match $party_id {
            0 => $expr0,
            1 => $expr1,
            _ => unreachable!("invalid party ID: {}", $party_id),
        }
    };
}
pub(crate) use branch_party;

/// A helper struct for processing settlements
#[derive(Clone)]
pub struct SettlementProcessor {
    /// The task context    
    pub ctx: TaskContext,
}

impl SettlementProcessor {
    /// Create a new settlement processor
    pub fn new(ctx: TaskContext) -> Self {
        Self { ctx }
    }

    // --- Helper Methods --- //

    /// Get the order for an order ID
    pub(crate) async fn get_order(&self, order_id: OrderId) -> Result<Order, SettlementError> {
        self.ctx
            .state
            .get_account_order(&order_id)
            .await?
            .ok_or_else(|| SettlementError::state(format!("order not found: {order_id}")))
    }

    // --- Auth Retrieval --- //

    /// Get the public intent auth (permit + signature) for an order
    async fn get_public_intent_auth(
        &self,
        order_id: OrderId,
    ) -> Result<(PublicIntentPermit, SignatureWithNonce), SettlementError> {
        let auth =
            self.ctx.state.get_order_auth(&order_id).await?.ok_or_else(|| {
                SettlementError::state(format!("order auth not found: {order_id}"))
            })?;
        Ok(auth.into_public())
    }

    /// Get the intent signature for a natively settled private order (Ring 1)
    async fn get_natively_settled_intent_auth(
        &self,
        order_id: OrderId,
    ) -> Result<SignatureWithNonce, SettlementError> {
        let auth =
            self.ctx.state.get_order_auth(&order_id).await?.ok_or_else(|| {
                SettlementError::state(format!("order auth not found: {order_id}"))
            })?;
        Ok(auth.into_natively_settled_private_order())
    }

    // --- Balance Retrieval --- //

    /// Get the input balance for a given party
    async fn get_input_balance(
        &self,
        account_id: AccountId,
        token: Address,
        location: BalanceLocation,
    ) -> Result<Balance, SettlementError> {
        let balance = self.ctx.state.get_account_balance(&account_id, &token, location).await?;
        balance.ok_or_else(|| {
            SettlementError::state(format!("input balance not found for account {account_id}"))
        })
    }

    /// Get the executor key to sign a settlement
    async fn get_executor_key(&self) -> Result<PrivateKeySigner, SettlementError> {
        self.ctx.state.get_executor_key().map_err(SettlementError::from)
    }

    /// Get the relayer fee for the match as a Solidity ABI `FeeRate`
    fn abi_relayer_fee(&self, base_token: &Token) -> Result<FeeRate, SettlementError> {
        let (rate, recipient) = self.relayer_fee(base_token)?;
        Ok(FeeRate { rate: rate.into(), recipient })
    }

    /// Get the relayer fee as circuit-types `FixedPoint` and recipient address
    ///
    /// Used for building settlement proof statements which require the
    /// circuit-level types rather than Solidity ABI types.
    fn relayer_fee(&self, base_token: &Token) -> Result<(FixedPoint, Address), SettlementError> {
        let ticker = base_token.get_ticker().ok_or_else(|| {
            SettlementError::state(format!("base token {base_token} has no ticker"))
        })?;

        let rate = self.ctx.state.get_relayer_fee(&ticker)?;
        let recipient = self.ctx.state.get_relayer_fee_addr()?;

        Ok((rate, recipient))
    }

    // --- State Updates --- //

    /// Update an intent after a match settlement
    pub async fn build_updated_intent(
        &self,
        order_id: OrderId,
        obligation: &SettlementObligation,
    ) -> Result<Order, SettlementError> {
        let mut order = self.get_order(order_id).await?;
        match order.ring {
            PrivacyRing::Ring0 => {
                self.update_ring0_intent_after_match(&mut order, obligation).await?
            },
            PrivacyRing::Ring1 => {
                self.update_ring1_intent_after_match(&mut order, obligation).await?
            },
            _ => unimplemented!("implementing updated intent for ring {:?}", order.ring),
        };
        Ok(order)
    }

    /// Update an order's state after a match settlement
    ///
    /// For Ring 0, this just decrements the amount remaining. For Ring 1+, this
    /// also updates the streams and public share so the stored order matches
    /// the post-settlement Merkle leaf.
    pub async fn update_order_after_match(&self, order: Order) -> Result<(), SettlementError> {
        let waiter = self.ctx.state.update_order(order).await?;
        waiter.await.map_err(SettlementError::from)?;
        Ok(())
    }

    /// Extract and store the Merkle authentication path for a Ring 1+ order
    /// from a settlement transaction receipt
    ///
    /// Computes the post-settlement intent commitment and looks it up in the
    /// receipt's Merkle insertion events. For Ring 0 orders this is a no-op.
    pub async fn update_intent_merkle_proof_after_match(
        &self,
        updated_order: &Order,
        receipt: &TransactionReceipt,
    ) -> Result<(), SettlementError> {
        if updated_order.ring == PrivacyRing::Ring0 {
            return Ok(());
        }

        // Extract the Merkle proof from the receipt
        let commitment = updated_order.intent.compute_commitment();
        let merkle_proof = self
            .ctx
            .darkpool_client
            .find_merkle_authentication_path_with_tx(commitment, receipt)
            .map_err(SettlementError::darkpool)?;

        // Store the Merkle proof
        let waiter = self.ctx.state.add_intent_merkle_proof(updated_order.id, merkle_proof).await?;
        waiter.await.map_err(SettlementError::from)?;
        Ok(())
    }

    /// Update the input balance for a given party
    pub async fn update_input_balance(
        &self,
        account_id: AccountId,
        location: BalanceLocation,
        obligation: &SettlementObligation,
    ) -> Result<(), SettlementError> {
        let state = &self.ctx.state;
        let mut balance =
            self.get_input_balance(account_id, obligation.input_token, location).await?;
        *balance.amount_mut() -= obligation.amount_in;

        // Write the balance back to the state
        let waiter = state.update_account_balance(account_id, balance).await?;
        waiter.await.map_err(SettlementError::from)?;
        Ok(())
    }
}
