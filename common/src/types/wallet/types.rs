//! Defines wallet types useful throughout the workspace

use std::{
    iter,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use circuit_types::{
    balance::Balance,
    fee::Fee,
    keychain::{PublicKeyChain, SecretIdentificationKey, SecretSigningKey},
    order::Order,
    SizedWallet as SizedCircuitWallet, SizedWalletShare,
};
use constants::{Scalar, MAX_FEES};
use derivative::Derivative;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{keyed_list::KeyedList, types::merkle::MerkleAuthenticationPath};

/// A type alias for the wallet identifier type, currently a UUID
pub type WalletIdentifier = Uuid;
/// An identifier of an order used for caching
pub type OrderIdentifier = Uuid;

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Eq)]
pub struct PrivateKeyChain {
    /// Optionally the relayer holds sk_root, in which case the relayer has
    /// heightened permissions than the standard case
    ///
    /// We call such a relayer a "super relayer"
    pub sk_root: Option<SecretSigningKey>,
    /// The match private key, authorizes the relayer to match orders for the
    /// wallet
    pub sk_match: SecretIdentificationKey,
}

/// Represents the public and private keys given to the relayer managing a
/// wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChain {
    /// The public keys in the wallet
    pub public_keys: PublicKeyChain,
    /// The secret keys in the wallet
    pub secret_keys: PrivateKeyChain,
}

/// The Merkle opening from the wallet shares' commitment to the global root
pub type WalletAuthenticationPath = MerkleAuthenticationPath;

/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Derivative, Deserialize)]
#[derivative(PartialEq)]
pub struct Wallet {
    /// The identifier used to index the wallet
    pub wallet_id: WalletIdentifier,
    /// A list of orders in this wallet
    ///
    /// We use an `IndexMap` here to preserve the order of insertion
    /// on the orders. This is necessary because we must have
    /// order parity with the secret shared wallet stored on-chain
    pub orders: KeyedList<OrderIdentifier, Order>,
    /// A mapping of mint to Balance information
    pub balances: KeyedList<BigUint, Balance>,
    /// A list of the fees in this wallet
    pub fees: Vec<Fee>,
    /// The keys that the relayer has access to for this wallet
    pub key_chain: KeyChain,
    /// The wallet blinder, used to blind secret shares the wallet holds
    pub blinder: Scalar,
    /// The private secret shares of the wallet
    pub private_shares: SizedWalletShare,
    /// The public secret shares of the wallet
    pub blinded_public_shares: SizedWalletShare,
    /// The authentication paths for the public and private shares of the wallet
    #[serde(default)]
    pub merkle_proof: Option<WalletAuthenticationPath>,
    /// The staleness of the Merkle proof, i.e. the number of Merkle root
    /// updates that have occurred since the wallet's Merkle proof was last
    /// updated
    #[serde(skip_serializing, skip_deserializing, default)]
    #[derivative(PartialEq = "ignore")]
    pub merkle_staleness: Arc<AtomicUsize>,
}

impl From<Wallet> for SizedCircuitWallet {
    fn from(wallet: Wallet) -> Self {
        SizedCircuitWallet {
            balances: wallet.get_balances_list(),
            orders: wallet.get_orders_list(),
            fees: wallet.get_fees_list(),
            keys: wallet.key_chain.public_keys,
            blinder: wallet.blinder,
        }
    }
}

impl Wallet {
    /// Get a list of fees in order in their circuit representation
    pub fn get_fees_list(&self) -> [Fee; MAX_FEES] {
        self.fees
            .clone()
            .into_iter()
            .chain(iter::repeat(Fee::default()))
            .take(MAX_FEES)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    /// Invalidate the Merkle opening of a wallet after an update
    pub(crate) fn invalidate_merkle_opening(&mut self) {
        self.merkle_proof = None;
        self.merkle_staleness.store(0, Ordering::Relaxed);
    }

    /// Remove default balances, orders, fees
    pub fn remove_default_elements(&mut self) {
        self.balances.retain(|_mint, balance| !balance.is_default());
        self.orders.retain(|_id, order| !order.is_default());
        self.fees.retain(|fee| !fee.is_default());
    }
}
