//! Wallet type and methods on the wallet
//!
//! Separated out to aid discoverability on implementations

// pub mod derivation;
pub mod keychain;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod order;
pub mod pair;

use std::collections::HashMap;

use alloy::primitives::Address;
use circuit_types::Amount;
use darkpool_types::balance::Balance;
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use uuid::Uuid;

#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with};

use crate::{MerkleAuthenticationPath, keychain::KeyChain, order::Order};

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

    /// Remove default balances
    pub fn remove_default_elements(&mut self) {
        let default_balance = Balance::default();
        self.balances.retain(|_mint, balance| *balance != default_balance);
        self.orders.retain(|_id, order| *order != Order::default());
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
        let bal_amt = self.balances.get(&order.input_token()).map(|b| b.amount).unwrap_or_default();
        Amount::min(bal_amt, order.intent.amount_in)
    }
}

// Implementations on the rkyv-derived type
#[cfg(feature = "rkyv")]
mod rkyv_order_impls {
    //! Implementations for accound orders on the rkyv-derived type
    use circuit_types::Amount;
    use rkyv::rend::unaligned::u128_ule;

    use crate::OrderId;

    use super::ArchivedAccount;
    use super::order::ArchivedOrder;

    impl ArchivedAccount {
        /// Get an order by its ID
        pub fn get_order(&self, id: &OrderId) -> Option<&ArchivedOrder> {
            self.orders.get(id)
        }

        /// Get the matchable amount for an order
        pub fn get_matchable_amount_for_order(
            &self,
            order: &ArchivedOrder,
        ) -> <Amount as rkyv::Archive>::Archived {
            let in_token = &order.intent.in_token;
            let bal_amt = self.balances.get(in_token).map(|b| b.amount).unwrap_or_default();
            let intent_amt = order.intent.amount_in;

            u128_ule::min(bal_amt, intent_amt)
        }
    }
}
