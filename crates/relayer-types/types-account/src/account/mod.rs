//! Wallet type and methods on the wallet
//!
//! Separated out to aid discoverability on implementations

pub mod balance;
pub mod deposit;
pub mod derivation;
pub mod error;
pub mod keychain;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod order;
pub mod pair;

use std::collections::HashMap;

use alloy::primitives::Address;
use circuit_types::{Amount, max_amount, schnorr::SchnorrPublicKey};
use darkpool_types::{
    balance::DarkpoolBalance, csprng::PoseidonCSPRNG, state_wrapper::StateWrapper,
};
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use uuid::Uuid;

#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with};

use crate::{MerkleAuthenticationPath, balance::Balance, keychain::KeyChain, order::Order};

pub use error::AccountError;

/// An identifier of an order used for caching
pub type OrderId = Uuid;
/// The name of a matching pool
pub type MatchingPoolName = String;

/// The Merkle opening from the wallet shares' commitment to the global root
pub type WalletAuthenticationPath = MerkleAuthenticationPath;

/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct Account {
    /// The identifier used to index the wallet
    pub id: AccountId,
    /// A list of orders in this account
    pub orders: HashMap<OrderId, Order>,
    /// A list of balances in this account
    #[cfg_attr(feature = "rkyv", rkyv(with = with::MapKV<AddressDef, with::Identity>))]
    pub balances: HashMap<Address, Balance>,
    /// The keychain for the account
    pub keychain: KeyChain,
}

impl Account {
    /// Create a new empty account from the given seed information
    pub fn new_empty_account(id: AccountId, keychain: KeyChain) -> Self {
        Self { id, orders: HashMap::new(), balances: HashMap::new(), keychain }
    }
}

// ----------
// | Orders |
// ----------

impl Account {
    /// Get an order by its ID
    pub fn get_order(&self, id: &OrderId) -> Option<&Order> {
        self.orders.get(id)
    }

    /// Get the matchable amount for an order
    ///
    /// This is the amount specified by the order, capped at the amount backed
    /// by the account's balance.
    pub fn get_matchable_amount_for_order(&self, order: &Order) -> Amount {
        let bal_amt =
            self.balances.get(&order.input_token()).map(|b| b.amount()).unwrap_or_default();
        Amount::min(bal_amt, order.intent.inner.amount_in)
    }
}

// ------------
// | Balances |
// ------------

impl Account {
    /// Whether the account has a balance for the given mint
    pub fn has_balance(&self, mint: &Address) -> bool {
        self.balances.contains_key(mint)
    }

    /// Get a balance by its mint
    pub fn get_balance(&self, mint: &Address) -> Option<&Balance> {
        self.balances.get(mint)
    }

    /// Deposit a balance into the account
    pub fn deposit_balance(&mut self, mint: Address, amount: Amount) -> Result<(), AccountError> {
        // Get the balance
        let bal = self
            .balances
            .get_mut(&mint)
            .ok_or(AccountError::balance(format!("Balance not found for mint: {mint}")))?;

        // Check its bounds
        if bal.amount() + amount > max_amount() {
            let curr_amt = bal.amount();
            let err_msg = format!("Deposit would exceed max amount: {curr_amt} + {amount}");
            return Err(AccountError::balance(err_msg));
        }

        *bal.amount_mut() += amount;
        Ok(())
    }

    /// Create a new balance for the account
    pub fn create_balance(
        &mut self,
        token: Address,
        owner: Address,
        fee_recipient: Address,
        authority: SchnorrPublicKey,
    ) {
        let share_stream = self.sample_share_stream_seed();
        let recovery_stream = self.sample_recovery_id_stream_seed();

        let bal_inner = DarkpoolBalance::new(token, owner, fee_recipient, authority);
        let state_wrapper = StateWrapper::new(bal_inner, share_stream.seed, recovery_stream.seed);
        let bal = Balance::new(state_wrapper);
        self.balances.insert(token, bal);
    }
}

// ------------
// | Keychain |
// ------------

impl Account {
    /// Sample a new recovery id stream seed from the master keychain
    pub fn sample_recovery_id_stream_seed(&mut self) -> PoseidonCSPRNG {
        self.keychain.secret_keys.sample_recovery_id_stream_seed()
    }

    /// Sample a new share stream seed from the master keychain
    pub fn sample_share_stream_seed(&mut self) -> PoseidonCSPRNG {
        self.keychain.secret_keys.sample_share_stream_seed()
    }
}

// Implementations on the rkyv-derived type
#[cfg(feature = "rkyv")]
mod rkyv_order_impls {
    //! Implementations for account orders on the rkyv-derived type
    use std::cmp::min;

    use circuit_types::Amount;
    use rkyv::rancor;

    use crate::OrderId;
    use crate::order::Order;

    use super::ArchivedAccount;
    use super::order::ArchivedOrder;

    impl ArchivedAccount {
        /// Get an order by its ID
        pub fn get_order(&self, id: &OrderId) -> Option<&ArchivedOrder> {
            self.orders.get(id)
        }

        /// Get an order and deserialize it
        pub fn get_order_deserialized(&self, id: &OrderId) -> Option<Order> {
            let order = self.get_order(id)?;
            rkyv::deserialize::<_, rancor::Error>(order).ok()
        }

        /// Get the matchable amount for an order
        pub fn get_matchable_amount_for_order(
            &self,
            order: &ArchivedOrder,
        ) -> <Amount as rkyv::Archive>::Archived {
            let in_token = &order.intent.inner.in_token;
            let bal_amt = self
                .balances
                .get(in_token)
                .map(|b| b.state_wrapper.inner.amount)
                .unwrap_or_default();
            let intent_amt = order.intent.inner.amount_in;

            min(bal_amt, intent_amt)
        }
    }
}
