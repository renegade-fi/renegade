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
    elgamal::EncryptionKey,
    fixed_point::FixedPoint,
    keychain::{PublicKeyChain, SecretIdentificationKey, SecretSigningKey},
    native_helpers::create_wallet_shares_with_randomness,
    order::Order,
    traits::BaseType,
    SizedWallet as SizedCircuitWallet, SizedWalletShare,
};
use constants::Scalar;
use derivative::Derivative;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::hash::PoseidonCSPRNG;
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
    /// The keys that the relayer has access to for this wallet
    pub key_chain: KeyChain,
    /// The wallet blinder, used to blind secret shares the wallet holds
    pub blinder: Scalar,
    /// The match fee that the owner has authorized the relayer to take
    pub match_fee: FixedPoint,
    /// The key of the cluster that the wallet has delegated management to
    pub managing_cluster: EncryptionKey,
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
            keys: wallet.key_chain.public_keys,
            match_fee: wallet.match_fee,
            managing_cluster: wallet.managing_cluster,
            blinder: wallet.blinder,
        }
    }
}

impl Wallet {
    /// Create a new empty wallet from the given seed information
    pub fn new_empty_wallet(
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        share_seed: Scalar,
        key_chain: KeyChain,
    ) -> Self {
        // Create a wallet with dummy shares, compute the shares, then update the wallet
        let mut zero_iter = iter::repeat(Scalar::zero());
        let dummy_shares = SizedWalletShare::from_scalars(&mut zero_iter);

        let mut wallet = Self {
            wallet_id,
            orders: KeyedList::new(),
            balances: KeyedList::new(),
            match_fee: FixedPoint::from_integer(0),
            managing_cluster: EncryptionKey::default(),
            key_chain,
            blinded_public_shares: dummy_shares.clone(),
            private_shares: dummy_shares,
            blinder: Scalar::zero(),
            merkle_proof: None,
            merkle_staleness: Arc::new(AtomicUsize::new(0)),
        };

        // Cast the wallet to a circuit type to use the circuit helpers
        let circuit_wallet: SizedCircuitWallet = wallet.clone().into();

        // Sample blinders and private shares
        let mut blinder_csprng = PoseidonCSPRNG::new(blinder_seed);
        let (blinder, blinder_private) = blinder_csprng.next_tuple().unwrap();

        let share_csprng = PoseidonCSPRNG::new(share_seed);
        let private_shares = share_csprng.take(SizedWalletShare::NUM_SCALARS).collect_vec();

        let (private_shares, blinded_public_shares) = create_wallet_shares_with_randomness(
            &circuit_wallet,
            blinder,
            blinder_private,
            private_shares,
        );
        wallet.private_shares = private_shares;
        wallet.blinded_public_shares = blinded_public_shares;
        wallet.blinder = blinder;

        wallet
    }

    /// Construct a new wallet from private shares and blinded public shares
    pub fn new_from_shares(
        wallet_id: WalletIdentifier,
        key_chain: KeyChain,
        blinded_public_shares: SizedWalletShare,
        private_shares: SizedWalletShare,
    ) -> Self {
        let blinder = blinded_public_shares.blinder + private_shares.blinder;
        let unblinded_public_shares = blinded_public_shares.unblind_shares(blinder);
        let recovered_wallet = unblinded_public_shares + private_shares.clone();

        // Construct a wallet from the recovered shares
        Wallet {
            wallet_id,
            orders: recovered_wallet.orders.iter().cloned().map(|o| (Uuid::new_v4(), o)).collect(),
            balances: recovered_wallet
                .balances
                .iter()
                .cloned()
                .map(|b| (b.mint.clone(), b))
                .collect(),
            key_chain,
            match_fee: recovered_wallet.match_fee,
            managing_cluster: recovered_wallet.managing_cluster,
            blinder: recovered_wallet.blinder,
            private_shares,
            blinded_public_shares,
            merkle_proof: None,
            merkle_staleness: Default::default(),
        }
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
    }
}
