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
pub mod order_auth;
pub mod pair;

use std::collections::HashMap;

use alloy::primitives::Address;
use circuit_types::{Amount, max_amount, schnorr::SchnorrPublicKey};
use darkpool_types::{
    balance::DarkpoolBalance, csprng::PoseidonCSPRNG, intent::Intent, state_wrapper::StateWrapper,
};
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use uuid::Uuid;

#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with};

use crate::{
    MerkleAuthenticationPath,
    balance::{Balance, BalanceLocation},
    keychain::KeyChain,
    order::{Order, OrderMetadata, PrivacyRing},
};

pub use error::AccountError;

/// An identifier of an order used for caching
pub type OrderId = Uuid;
/// The name of a matching pool
pub type MatchingPoolName = String;

/// The Merkle opening from the wallet shares' commitment to the global root
pub type WalletAuthenticationPath = MerkleAuthenticationPath;
/// The balance map type
///
/// We nest maps here to allow for the type to be archived correctly.
pub type BalanceMap = HashMap<Address, HashMap<BalanceLocation, Balance>>;

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
    pub balances: BalanceMap,
    /// The keychain for the account
    pub keychain: KeyChain,
}

impl Account {
    /// Create a new empty account from the given seed information
    pub fn new_empty_account(id: AccountId, keychain: KeyChain) -> Self {
        Self { id, orders: HashMap::new(), balances: HashMap::new(), keychain }
    }

    /// Create an account from balances, orders, keychain, id
    pub fn new(
        id: AccountId,
        orders: Vec<Order>,
        balances: Vec<Balance>,
        keychain: KeyChain,
    ) -> Self {
        let mut orders_map = HashMap::new();
        for order in orders {
            orders_map.insert(order.id, order);
        }

        let mut balances_map = HashMap::new();
        for balance in balances {
            let loc_map: &mut HashMap<BalanceLocation, Balance> =
                balances_map.entry(balance.mint()).or_default();
            loc_map.insert(balance.location, balance);
        }

        Self { id, orders: orders_map, balances: balances_map, keychain }
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
        let token = order.input_token();
        let location = order.ring.balance_location();
        let bal = self.get_balance(&token, location).map(|b| b.amount()).unwrap_or_default();
        Amount::min(bal, order.intent.inner.amount_in)
    }

    /// Place an order into the account
    pub fn place_order(
        &mut self,
        id: OrderId,
        intent: Intent,
        ring: PrivacyRing,
        metadata: OrderMetadata,
    ) {
        let share_stream = self.sample_share_stream_seed();
        let recovery_stream = self.sample_recovery_id_stream_seed();
        let wrapper = StateWrapper::new(intent, share_stream.seed, recovery_stream.seed);

        let order = Order::new_with_ring(id, wrapper, metadata, ring);
        self.orders.insert(order.id, order);
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

    /// Get the EOA balance for an account by its mint
    pub fn get_eoa_balance(&self, mint: &Address) -> Option<&Balance> {
        self.balances.get(mint).and_then(|b| b.get(&BalanceLocation::EOA))
    }

    /// Get a mutable reference to the EOA balance for an account by its mint
    pub fn get_eoa_balance_mut(&mut self, mint: &Address) -> Option<&mut Balance> {
        self.balances.get_mut(mint).and_then(|b| b.get_mut(&BalanceLocation::EOA))
    }

    /// Get the darkpool balance for an account by its mint
    pub fn get_darkpool_balance(&self, mint: &Address) -> Option<&Balance> {
        self.balances.get(mint).and_then(|b| b.get(&BalanceLocation::Darkpool))
    }

    /// Get a mutable reference to the darkpool balance for an account by its
    /// mint
    pub fn get_darkpool_balance_mut(&mut self, mint: &Address) -> Option<&mut Balance> {
        self.balances.get_mut(mint).and_then(|b| b.get_mut(&BalanceLocation::Darkpool))
    }

    /// Get the balance for an account by its mint and location
    pub fn get_balance(&self, mint: &Address, location: BalanceLocation) -> Option<&Balance> {
        self.balances.get(mint).and_then(|b| b.get(&location))
    }

    /// Get a mutable reference to the balance for an account by its mint and
    /// location
    pub fn get_balance_mut(
        &mut self,
        mint: &Address,
        location: BalanceLocation,
    ) -> Option<&mut Balance> {
        self.balances.get_mut(mint).and_then(|b| b.get_mut(&location))
    }

    /// Get all balances in the account
    pub fn get_all_balances(&self) -> Vec<Balance> {
        let mut balances = Vec::new();
        for loc_map in self.balances.values() {
            for balance in loc_map.values() {
                balances.push(balance.clone());
            }
        }

        balances
    }

    // --- Setters --- //

    /// Deposit a balance into the account
    pub fn deposit_balance(
        &mut self,
        mint: Address,
        amount: Amount,
        location: BalanceLocation,
    ) -> Result<(), AccountError> {
        // Get the balance
        let bal = match location {
            BalanceLocation::EOA => self.get_eoa_balance_mut(&mint),
            BalanceLocation::Darkpool => self.get_darkpool_balance_mut(&mint),
        }
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
        location: BalanceLocation,
    ) {
        let share_stream = self.sample_share_stream_seed();
        let recovery_stream = self.sample_recovery_id_stream_seed();

        let bal_inner = DarkpoolBalance::new(token, owner, fee_recipient, authority);
        let state_wrapper = StateWrapper::new(bal_inner, share_stream.seed, recovery_stream.seed);
        let bal = Balance::new(state_wrapper, location);

        // Insert the balance into the nested map
        let loc_map = self.balances.entry(token).or_default();
        loc_map.insert(location, bal);
    }

    /// Create a new EOA balance for the account
    pub fn create_eoa_balance(
        &mut self,
        token: Address,
        owner: Address,
        fee_recipient: Address,
        authority: SchnorrPublicKey,
    ) {
        self.create_balance(token, owner, fee_recipient, authority, BalanceLocation::EOA);
    }

    /// Create a new darkpool balance for the account
    pub fn create_darkpool_balance(
        &mut self,
        token: Address,
        owner: Address,
        fee_recipient: Address,
        authority: SchnorrPublicKey,
    ) {
        self.create_balance(token, owner, fee_recipient, authority, BalanceLocation::Darkpool);
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
    use darkpool_types::rkyv_remotes::ArchivedAddress;
    use rkyv::rancor;

    use crate::OrderId;
    use crate::balance::{ArchivedBalance, ArchivedBalanceLocation};
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

        /// Get the EOA balance for an account by its mint
        pub fn get_eoa_balance(&self, mint: &ArchivedAddress) -> Option<&ArchivedBalance> {
            self.balances.get(mint).and_then(|b| b.get(&ArchivedBalanceLocation::EOA))
        }

        /// Get the darkpool balance for an account by its mint
        pub fn get_darkpool_balance(&self, mint: &ArchivedAddress) -> Option<&ArchivedBalance> {
            self.balances.get(mint).and_then(|b| b.get(&ArchivedBalanceLocation::Darkpool))
        }

        /// Get the balance for an account by its mint and location
        pub fn get_balance(
            &self,
            mint: &ArchivedAddress,
            location: &ArchivedBalanceLocation,
        ) -> Option<&ArchivedBalance> {
            self.balances.get(mint).and_then(|b| b.get(location))
        }

        /// Get the matchable amount for an order
        pub fn get_matchable_amount_for_order(
            &self,
            order: &ArchivedOrder,
        ) -> <Amount as rkyv::Archive>::Archived {
            let in_token = &order.intent.inner.in_token;
            let location = order.ring.balance_location();
            let bal = self
                .get_balance(in_token, &location)
                .map(|b| b.amount_archived())
                .unwrap_or_default();

            let intent_amt = order.intent.inner.amount_in;
            min(bal, intent_amt)
        }
    }
}
