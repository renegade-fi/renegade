//! Defines wallet types useful throughout the workspace

use std::{
    collections::HashSet,
    hash::Hash,
    iter,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use circuit_types::{
    balance::Balance,
    fee::Fee,
    keychain::{PublicKeyChain, SecretIdentificationKey, SecretSigningKey},
    native_helpers::{
        compute_wallet_private_share_commitment, compute_wallet_share_commitment,
        compute_wallet_share_nullifier, create_wallet_shares_from_private,
    },
    order::{Order, OrderSide},
    traits::BaseType,
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment},
    SizedWallet as SizedCircuitWallet, SizedWalletShare,
};
use constants::{Scalar, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use derivative::Derivative;
use indexmap::IndexMap;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::hash::evaluate_hash_chain;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::log;
use uuid::Uuid;

use super::{gossip::WrappedPeerId, merkle::MerkleAuthenticationPath};

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
    #[serde(serialize_with = "serialize_indexmap", deserialize_with = "deserialize_indexmap")]
    pub orders: IndexMap<OrderIdentifier, Order>,
    /// A mapping of mint to Balance information
    #[serde(serialize_with = "serialize_indexmap", deserialize_with = "deserialize_indexmap")]
    pub balances: IndexMap<BigUint, Balance>,
    /// A list of the fees in this wallet
    pub fees: Vec<Fee>,
    /// The keys that the relayer has access to for this wallet
    pub key_chain: KeyChain,
    /// The wallet blinder, used to blind secret shares the wallet holds
    pub blinder: Scalar,
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    /// The private secret shares of the wallet
    pub private_shares: SizedWalletShare,
    /// The public secret shares of the wallet
    pub blinded_public_shares: SizedWalletShare,
    /// The authentication paths for the public and private shares of the wallet
    #[serde(default)]
    pub merkle_proof: Option<WalletAuthenticationPath>,
    /// An update lock, used to protect against concurrent updates to a wallet
    ///
    /// `true` implies that the lock is held elsewhere
    ///
    /// TODO: Remove this in favor of a more robust update dependency solution
    /// once the state has been refactored to a raft-based consensus
    #[derivative(PartialEq = "ignore")]
    #[serde(skip_serializing, skip_deserializing, default = "default_update_lock")]
    pub update_locked: Arc<AtomicBool>,
}

/// A custom default method that serde uses for deserialization; simply creates
/// a new lock that is initialized unlocked
///
/// TODO: Remove this when we remove the field
fn default_update_lock() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::default())
}

/// Custom serialization for an `IndexMap` type that preserves insertion
/// ordering
fn serialize_indexmap<S, K, V>(map: &IndexMap<K, V>, s: S) -> Result<S::Ok, S::Error>
where
    K: Serialize + Clone,
    V: Serialize + Clone,
    S: Serializer,
{
    // Convert to a vector of key-value pairs to preserve ordering
    let vec: Vec<(K, V)> = map.clone().into_iter().collect();
    vec.serialize(s)
}

/// Custom deserialization for an `IndexMap` type that preserves insertion
/// ordering
fn deserialize_indexmap<'de, D, K, V>(d: D) -> Result<IndexMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Eq + Hash,
    V: Deserialize<'de>,
{
    let vec: Vec<(K, V)> = Vec::deserialize(d)?;
    Ok(vec.into_iter().collect())
}

impl From<Wallet> for SizedCircuitWallet {
    fn from(wallet: Wallet) -> Self {
        SizedCircuitWallet {
            balances: wallet
                .balances
                .into_values()
                .chain(iter::repeat(Balance::default()))
                .take(MAX_BALANCES)
                .collect_vec()
                .try_into()
                .unwrap(),
            orders: wallet
                .orders
                .into_values()
                .chain(iter::repeat(Order::default()))
                .take(MAX_ORDERS)
                .collect_vec()
                .try_into()
                .unwrap(),
            fees: wallet
                .fees
                .into_iter()
                .chain(iter::repeat(Fee::default()))
                .take(MAX_FEES)
                .collect_vec()
                .try_into()
                .unwrap(),
            keys: wallet.key_chain.public_keys,
            blinder: wallet.blinder,
        }
    }
}

// TODO: Remove wallet locking methods
impl Wallet {
    /// Try to lock the wallet for an update
    ///
    /// Returns `true` if the update succeeded
    pub fn try_lock_wallet(&self) -> bool {
        log::debug!("locking wallet: {}", self.wallet_id,);

        self.update_locked
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Unlock the wallet
    pub fn unlock_wallet(&self) -> bool {
        log::debug!("unlocking wallet: {}", self.wallet_id);
        self.update_locked
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Check if the wallet is locked
    pub fn is_locked(&self) -> bool {
        self.update_locked.load(Ordering::Relaxed)
    }

    /// Computes the commitment to the private shares of the wallet
    pub fn get_private_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_private_share_commitment(&self.private_shares)
    }

    /// Compute the commitment to the full wallet shares
    pub fn get_wallet_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_share_commitment(&self.blinded_public_shares, &self.private_shares)
    }

    /// Compute the wallet nullifier
    pub fn get_wallet_nullifier(&self) -> Nullifier {
        compute_wallet_share_nullifier(self.get_wallet_share_commitment(), self.blinder)
    }

    /// Reblind the wallet, consuming the next set of blinders and secret shares
    pub fn reblind_wallet(&mut self) {
        let private_shares_serialized: Vec<Scalar> = self.private_shares.to_scalars();

        // Sample a new blinder and private secret share
        let n_shares = private_shares_serialized.len();
        let blinder_and_private_share =
            evaluate_hash_chain(private_shares_serialized[n_shares - 1], 2 /* length */);
        let new_blinder = blinder_and_private_share[0];
        let new_blinder_private_share = blinder_and_private_share[1];

        // Sample new secret shares for the wallet
        let mut new_private_shares =
            evaluate_hash_chain(private_shares_serialized[n_shares - 2], n_shares - 1);
        new_private_shares.push(new_blinder_private_share);

        let (new_private_share, new_public_share) = create_wallet_shares_from_private(
            &self.clone().into(),
            &WalletShare::from_scalars(&mut new_private_shares.into_iter()),
            new_blinder,
        );

        self.private_shares = new_private_share;
        self.blinded_public_shares = new_public_share;
        self.blinder = new_blinder;
    }

    /// Remove default balances, orders, fees
    pub fn remove_default_elements(&mut self) {
        self.balances.retain(|_mint, balance| !balance.is_default());
        self.orders.retain(|_id, order| !order.is_default());
        self.fees.retain(|fee| !fee.is_default());
    }

    /// Get the balance, fee, and fee_balance for an order by specifying the
    /// order directly
    ///
    /// We allow orders to be matched when undercapitalized; i.e. the respective
    /// balance does not cover the full volume of the order.
    pub fn get_balance_and_fee_for_order(&self, order: &Order) -> Option<(Balance, Fee, Balance)> {
        // The mint the local party will be spending if the order is matched
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint.clone(),
            OrderSide::Sell => order.base_mint.clone(),
        };

        // Find a balance and fee to associate with this order
        // Choose the first fee for simplicity
        let balance = self.balances.get(&order_mint)?;

        // Choose the first non-default fee
        let fee = self.fees.iter().find(|fee| !fee.is_default())?;
        let fee_balance = self.balances.get(&fee.gas_addr.clone())?;
        if fee_balance.amount < fee.gas_token_amount {
            return None;
        }

        Some((balance.clone(), fee.clone(), fee_balance.clone()))
    }
}

/// Metadata relevant to the wallet's network state
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given
    /// wallet
    pub replicas: HashSet<WrappedPeerId>,
}

/// Defines mocks for the wallet used in testing
#[cfg(feature = "mocks")]
pub mod mocks {
    use std::{
        iter,
        sync::{atomic::AtomicBool, Arc},
    };

    use circuit_types::{
        keychain::{
            PublicIdentificationKey, PublicKeyChain, PublicSigningKey, SecretIdentificationKey,
        },
        traits::BaseType,
        SizedWalletShare,
    };
    use constants::{Scalar, MERKLE_HEIGHT};
    use indexmap::IndexMap;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use uuid::Uuid;

    use crate::types::merkle::MerkleAuthenticationPath;

    use super::{KeyChain, PrivateKeyChain, Wallet, WalletMetadata};

    /// Create a mock empty wallet
    pub fn mock_empty_wallet() -> Wallet {
        // Create an initial wallet
        let mut rng = thread_rng();
        let mut wallet = Wallet {
            wallet_id: Uuid::new_v4(),
            orders: IndexMap::default(),
            balances: IndexMap::default(),
            fees: vec![],
            key_chain: KeyChain {
                public_keys: PublicKeyChain {
                    pk_root: PublicSigningKey::from(&BigUint::from(0u8)),
                    pk_match: PublicIdentificationKey::from(Scalar::zero()),
                },
                secret_keys: PrivateKeyChain {
                    sk_root: None,
                    sk_match: SecretIdentificationKey::from(Scalar::zero()),
                },
            },
            blinder: Scalar::random(&mut rng),
            private_shares: SizedWalletShare::from_scalars(&mut iter::repeat(Scalar::random(
                &mut rng,
            ))),
            blinded_public_shares: SizedWalletShare::from_scalars(&mut iter::repeat(
                Scalar::random(&mut rng),
            )),
            metadata: WalletMetadata::default(),
            merkle_proof: Some(mock_merkle_path()),
            update_locked: Arc::new(AtomicBool::default()),
        };

        // Reblind the wallet so that the secret shares a valid sharing of the wallet
        wallet.reblind_wallet();
        wallet
    }

    /// Create a mock Merkle path for a wallet
    pub fn mock_merkle_path() -> MerkleAuthenticationPath {
        MerkleAuthenticationPath::new(
            [Scalar::zero(); MERKLE_HEIGHT],
            BigUint::from(0u8),
            Scalar::zero(),
        )
    }
}
