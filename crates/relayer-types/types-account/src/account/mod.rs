//! Wallet type and methods on the wallet
//!
//! Separated out to aid discoverability on implementations

// pub mod derivation;
pub mod keychain;
#[cfg(feature = "mocks")]
pub mod mocks;

use std::collections::HashMap;

use alloy::primitives::Address;
use darkpool_types::{balance::Balance, intent::Intent};
use serde::{Deserialize, Serialize};
use types_core::AccountId;
use uuid::Uuid;

#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with};

use crate::MerkleAuthenticationPath;

/// An identifier of an order used for caching
pub type IntentIdentifier = Uuid;
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
    pub wallet_id: AccountId,
    /// A list of intents in this account
    pub intents: HashMap<IntentIdentifier, Intent>,
    /// A list of balances in this account
    #[cfg_attr(feature = "rkyv", rkyv(with = with::MapKV<AddressDef, with::Identity>))]
    pub balances: HashMap<Address, Balance>,
}

impl Account {
    /// Create a new empty account from the given seed information
    pub fn new_empty_account(wallet_id: AccountId) -> Self {
        Self { wallet_id, intents: HashMap::new(), balances: HashMap::new() }
    }

    /// Remove default balances
    pub fn remove_default_elements(&mut self) {
        let default_balance = Balance::default();
        self.balances.retain(|_mint, balance| *balance != default_balance);
        self.intents.retain(|_id, intent| *intent != Intent::default());
    }
}
