//! Defines wallet types useful throughout the workspace

use std::{
    iter,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use circuit_types::{
    balance::Balance, elgamal::EncryptionKey, fixed_point::FixedPoint,
    native_helpers::create_wallet_shares_with_randomness, order::Order as CircuitOrder,
    traits::BaseType, SizedWallet as SizedCircuitWallet, SizedWalletShare,
};
use constants::Scalar;
use derivative::Derivative;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::hash::PoseidonCSPRNG;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{keyed_list::KeyedList, types::merkle::MerkleAuthenticationPath};

use super::{
    keychain::{KeyChain, PrivateKeyChain},
    orders::Order,
};

/// A type alias for the wallet identifier type, currently a UUID
pub type WalletIdentifier = Uuid;
/// An identifier of an order used for caching
pub type OrderIdentifier = Uuid;

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
        let orders_vec = wallet.get_orders_list().into_iter().map(CircuitOrder::from).collect_vec();
        let orders = orders_vec.try_into().expect("get_orders_list returned more than MAX_ORDERS");
        SizedCircuitWallet {
            balances: wallet.get_balances_list(),
            orders,
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
        secret_keys: PrivateKeyChain,
        blinded_public_shares: SizedWalletShare,
        private_shares: SizedWalletShare,
    ) -> Self {
        let blinder = blinded_public_shares.blinder + private_shares.blinder;
        let unblinded_public_shares = blinded_public_shares.unblind_shares(blinder);
        let recovered_wallet = unblinded_public_shares + private_shares.clone();
        let key_chain = KeyChain { public_keys: recovered_wallet.keys, secret_keys };

        // Construct a wallet from the recovered shares
        let orders = recovered_wallet
            .orders
            .into_iter()
            .map(|o| (OrderIdentifier::new_v4(), o.into()))
            .collect();

        Wallet {
            wallet_id,
            orders,
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
