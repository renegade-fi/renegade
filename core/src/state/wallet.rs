//! Groups state primitives for indexing and tracking wallet information

use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    iter,
    sync::atomic::{AtomicU32, Ordering},
};

use circuits::{
    native_helpers::{
        compute_poseidon_hash, compute_wallet_private_share_commitment,
        compute_wallet_share_commitment, compute_wallet_share_nullifier,
        create_wallet_shares_from_private,
    },
    traits::BaseType,
    types::{
        balance::Balance,
        fee::Fee,
        keychain::{PublicKeyChain, SecretIdentificationKey, SecretSigningKey},
        order::{Order, OrderSide},
        wallet::{Nullifier, Wallet as CircuitWallet, WalletShare, WalletShareStateCommitment},
    },
    zk_gadgets::merkle::MerkleOpening,
};
use crypto::hash::evaluate_hash_chain;
use curve25519_dalek::scalar::Scalar;
use futures::{stream::iter as to_stream, StreamExt};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{de::Error as SerdeErr, Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

use crate::{
    gossip::types::WrappedPeerId, SizedMerkleOpening, SizedWalletShare, MAX_BALANCES, MAX_FEES,
    MAX_ORDERS, MERKLE_HEIGHT, MERKLE_ROOT_HISTORY_LENGTH,
};

use super::{new_async_shared, orderbook::OrderIdentifier, AsyncShared, MerkleTreeCoords};

/// The staleness factor; the ratio of the root history that has elapsed before new proofs of
/// `VALID COMMITMENTS` and `VALID REBLIND` are required for an order
const ROOT_HISTORY_STALENESS_FACTOR: f32 = 0.75;

lazy_static! {
    /// The staleness threshold at which new proofs of `VALID COMMITMENTS` should be generated
    static ref STALENESS_THRESHOLD: u32 = {
        let threshold_f32 = ROOT_HISTORY_STALENESS_FACTOR * (MERKLE_ROOT_HISTORY_LENGTH as f32);
        threshold_f32 as u32
    };
}

// --------------------------
// | State Type Definitions |
// --------------------------

/// A type that attaches default size parameters to a circuit allocated wallet
type SizedCircuitWallet = CircuitWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A type alias for the wallet identifier type, currently a UUID
pub type WalletIdentifier = Uuid;

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeyChain {
    /// Optionally the relayer holds sk_root, in which case the relayer has
    /// heightened permissions than the standard case
    ///
    /// We call such a relayer a "super relayer"
    pub sk_root: Option<SecretSigningKey>,
    /// The match private key, authorizes the relayer to match orders for the wallet
    pub sk_match: SecretIdentificationKey,
}

/// Represents the public and private keys given to the relayer managing a wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChain {
    /// The public keys in the wallet
    pub public_keys: PublicKeyChain,
    /// The secret keys in the wallet
    pub secret_keys: PrivateKeyChain,
}

/// Represents a Merkle authentication path for a wallet
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MerkleAuthenticationPath {
    /// A list of sibling node values that are hashed with
    /// the wallet commitment in the root computation
    ///
    /// The first value in this list is a leaf, the last value is
    /// one of the root's children
    pub path_siblings: [Scalar; MERKLE_HEIGHT],
    /// The leaf index that this node sits at
    pub leaf_index: BigUint,
    /// The value being authenticated
    pub value: Scalar,
}

impl MerkleAuthenticationPath {
    /// Constructor
    pub fn new(path_siblings: [Scalar; MERKLE_HEIGHT], leaf_index: BigUint, value: Scalar) -> Self {
        Self {
            path_siblings,
            leaf_index,
            value,
        }
    }

    /// Static helper method to get the coordinates of a Merkle authentication path from
    /// the leaf value
    pub fn construct_path_coords(leaf_index: BigUint, height: usize) -> Vec<MerkleTreeCoords> {
        let mut coords = Vec::with_capacity(height);
        let mut curr_height_index = leaf_index;
        for height in (1..height + 1).rev() {
            // If the LSB of the node index at the current height is zero, the node
            // is a left hand child. If the LSB is one, it is a right hand child.
            // Choose the index of its sibling
            let sibling_index = if &curr_height_index % 2u8 == BigUint::from(0u8) {
                &curr_height_index + 1u8
            } else {
                &curr_height_index - 1u8
            };

            coords.push(MerkleTreeCoords::new(height, sibling_index));
            curr_height_index >>= 1;
        }

        coords
    }

    /// Compute the coordinates of the wallet's authentication path in the tree
    ///
    /// The result is sorted from leaf level to depth 1
    pub fn compute_authentication_path_coords(&self) -> Vec<MerkleTreeCoords> {
        let mut current_index = self.leaf_index.clone();

        let mut coords = Vec::with_capacity(MERKLE_HEIGHT);
        for height in (1..MERKLE_HEIGHT + 1).rev() {
            let sibling_index = if &current_index % 2u8 == BigUint::from(0u8) {
                // Left hand node
                &current_index + 1u8
            } else {
                // Right hand node
                &current_index - 1u8
            };

            coords.push(MerkleTreeCoords::new(height, sibling_index));
            current_index >>= 1u8;
        }

        coords
    }

    /// Compute the root implied by the path
    pub fn compute_root(&self) -> Scalar {
        let mut current_index = self.leaf_index.clone();
        let mut current_value = self.value;

        for sibling in self.path_siblings.iter() {
            current_value = if &current_index % 2u8 == BigUint::from(0u8) {
                compute_poseidon_hash(&[current_value, *sibling])
            } else {
                compute_poseidon_hash(&[*sibling, current_value])
            };

            current_index >>= 1;
        }

        current_value
    }
}

/// Conversion to circuit type
impl From<MerkleAuthenticationPath> for SizedMerkleOpening {
    fn from(native_path: MerkleAuthenticationPath) -> Self {
        // The path conversion is simply the first `MERKLE_HEIGHT` bits of
        // the leaf index
        let path_indices = (0..MERKLE_HEIGHT)
            .map(|bit| native_path.leaf_index.bit(bit as u64))
            .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
            .collect_vec();

        MerkleOpening {
            elems: native_path.path_siblings.to_vec().try_into().unwrap(),
            indices: path_indices.try_into().unwrap(),
        }
    }
}

/// The Merkle opening from the wallet shares' commitment to the global root
pub type WalletAuthenticationPath = MerkleAuthenticationPath;

/// Represents a wallet managed by the local relayer
#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// The identifier used to index the wallet
    pub wallet_id: WalletIdentifier,
    /// A list of orders in this wallet
    pub orders: HashMap<OrderIdentifier, Order>,
    /// A mapping of mint to Balance information
    #[serde(
        serialize_with = "serialize_balances",
        deserialize_with = "deserialize_balances"
    )]
    pub balances: HashMap<BigUint, Balance>,
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
    /// The staleness of the valid commitments proof for each order in
    /// the wallet, i.e. the number of new roots that have been seen
    /// on-chain since `VALID COMMITMENTS` was last proved for this wallet
    #[serde(default)]
    pub proof_staleness: AtomicU32,
}

/// Custom clone implementation, cannot be derived with the AtomicU32
impl Clone for Wallet {
    fn clone(&self) -> Self {
        let staleness = self.proof_staleness.load(Ordering::Relaxed);

        Self {
            wallet_id: self.wallet_id,
            orders: self.orders.clone(),
            balances: self.balances.clone(),
            fees: self.fees.clone(),
            key_chain: self.key_chain.clone(),
            blinder: self.blinder,
            metadata: self.metadata.clone(),
            private_shares: self.private_shares.clone(),
            blinded_public_shares: self.blinded_public_shares.clone(),
            merkle_proof: self.merkle_proof.clone(),
            proof_staleness: AtomicU32::new(staleness),
        }
    }
}

/// Custom serialization logic for the balance map that re-keys the map via String
fn serialize_balances<S>(balances: &HashMap<BigUint, Balance>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert to a hashmap keyed by strings
    let string_keyed_map: HashMap<String, Balance> = balances
        .clone()
        .into_iter()
        .map(|(mint, balance)| (mint.to_string(), balance))
        .collect();
    string_keyed_map.serialize(s)
}

/// Custom deserialization logic for the balance map that re-keys from String to BigUint
fn deserialize_balances<'de, D>(d: D) -> Result<HashMap<BigUint, Balance>, D::Error>
where
    D: Deserializer<'de>,
{
    let string_keyed_map: HashMap<String, Balance> = HashMap::deserialize(d)?;
    let mut bigint_keyed_map = HashMap::new();

    for (k, balance) in string_keyed_map.into_iter() {
        let key_stripped = k.strip_prefix("0x").unwrap_or(&k);
        let bigint_key = BigUint::from_str_radix(key_stripped, 16 /* radix */)
            .map_err(|err| SerdeErr::custom(err.to_string()))?;
        bigint_keyed_map.insert(bigint_key, balance);
    }

    Ok(bigint_keyed_map)
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

impl Wallet {
    /// Computes the commitment to the private shares of the wallet
    pub fn get_private_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_private_share_commitment(self.private_shares.clone())
    }

    /// Compute the commitment to the full wallet shares
    pub fn get_wallet_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_share_commitment(
            self.blinded_public_shares.clone(),
            self.private_shares.clone(),
        )
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
            self.clone().into(),
            &WalletShare::from_scalars(&mut new_private_shares.into_iter()),
            new_blinder,
        );

        self.private_shares = new_private_share;
        self.blinded_public_shares = new_public_share;
        self.blinder = new_blinder;
    }

    /// Decides whether the wallet's orders need new commitment proofs
    ///
    /// When the Merkle roots get too stale, we need to re-prove the
    /// `VALID COMMITMENTS` entry for each order in the wallet and `VALID REBLIND`
    /// for the wallet itself on a fresh root that the contract will have stored
    /// when matches occur
    ///
    /// This method, although simple, is written abstractly to allow us to change
    /// the logic that decides this down the line
    pub fn needs_new_commitment_proof(&self) -> bool {
        let staleness = self.proof_staleness.load(Ordering::Relaxed);
        staleness > *STALENESS_THRESHOLD
    }

    /// Remove default balances, orders, fees
    pub fn remove_default_elements(&mut self) {
        self.balances.retain(|_mint, balance| !balance.is_default());
        self.orders.retain(|_id, order| !order.is_default());
        self.fees.retain(|fee| !fee.is_default());
    }

    /// Get the balance, fee, and fee_balance for an order by specifying the order directly
    ///
    /// This is useful for new orders that come in, and are not yet indexed in the global state
    pub fn get_balance_and_fee_for_order(&self, order: &Order) -> Option<(Balance, Fee, Balance)> {
        // The mint the local party will be spending if the order is matched
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint.clone(),
            OrderSide::Sell => order.base_mint.clone(),
        };

        // The maximum quantity of the mint that the local party will be spending
        let order_amount = match order.side {
            OrderSide::Buy => {
                let res_amount = (order.amount as f64) * order.price.to_f64();
                res_amount as u64
            }
            OrderSide::Sell => order.amount,
        };

        // Find a balance and fee to associate with this order
        // Choose the first fee for simplicity
        let balance = self.balances.get(&order_mint)?;
        if balance.amount < order_amount {
            return None;
        }

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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given wallet
    pub replicas: HashSet<WrappedPeerId>,
}

// ------------------
// | State Indexing |
// ------------------

/// An abstraction over a set of wallets that indexes wallets and de-normalizes
/// their data
#[derive(Clone, Debug)]
pub struct WalletIndex {
    /// The peer_id of the local node
    peer_id: WrappedPeerId,
    /// A mapping from wallet ID to wallet information
    wallet_map: HashMap<Uuid, AsyncShared<Wallet>>,
    /// A reverse index mapping from order to wallet
    order_to_wallet: HashMap<OrderIdentifier, WalletIdentifier>,
}

impl WalletIndex {
    /// Create a wallet index
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self {
            peer_id,
            wallet_map: HashMap::new(),
            order_to_wallet: HashMap::new(),
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on a wallet
    pub async fn read_wallet(&self, wallet_id: &Uuid) -> Option<RwLockReadGuard<Wallet>> {
        if let Some(locked_wallet) = self.wallet_map.get(wallet_id) {
            Some(locked_wallet.read().await)
        } else {
            None
        }
    }

    /// Acquire a write lock on a wallet
    pub async fn write_wallet(&self, wallet_id: &Uuid) -> Option<RwLockWriteGuard<Wallet>> {
        if let Some(locked_wallet) = self.wallet_map.get(wallet_id) {
            Some(locked_wallet.write().await)
        } else {
            None
        }
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the wallet with the given ID
    pub async fn get_wallet(&self, wallet_id: &WalletIdentifier) -> Option<Wallet> {
        self.read_wallet(wallet_id)
            .await
            .map(|locked_val| locked_val.clone())
    }

    /// Get the wallet that an order is allocated in
    pub fn get_wallet_for_order(&self, order_id: &OrderIdentifier) -> Option<WalletIdentifier> {
        self.order_to_wallet.get(order_id).cloned()
    }

    /// Get all the wallet ids that are indexed
    pub fn get_all_wallet_ids(&self) -> Vec<WalletIdentifier> {
        self.wallet_map.keys().cloned().collect_vec()
    }

    /// Returns a list of all wallets
    pub async fn get_all_wallets(&self) -> Vec<Wallet> {
        to_stream(self.wallet_map.values().cloned())
            .then(|locked_wallet| async move { locked_wallet.read().await.clone() })
            .collect::<Vec<_>>()
            .await
    }

    /// Returns a mapping from wallet ID to the wallet's metadata
    ///
    /// Used to serialize into the handshake response
    pub async fn get_metadata_map(&self) -> HashMap<WalletIdentifier, WalletMetadata> {
        let mut res = HashMap::new();
        for (id, wallet) in self.wallet_map.iter() {
            res.insert(*id, wallet.read().await.metadata.clone());
        }

        res
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a concurrency safe wallet to the index
    pub fn add_wallet(&mut self, mut wallet: Wallet) {
        // Add orders in the wallet to the inverse mapping
        for order_id in wallet.orders.keys() {
            self.order_to_wallet.insert(*order_id, wallet.wallet_id);
        }

        // Index the wallet
        wallet.metadata.replicas.insert(self.peer_id);
        self.wallet_map
            .insert(wallet.wallet_id, new_async_shared(wallet));
    }

    /// Add a given peer as a replica of a wallet
    pub async fn add_replica(&self, wallet_id: &WalletIdentifier, peer_id: WrappedPeerId) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet.write().await.metadata.replicas.insert(peer_id);
        }
    }

    /// Add a Merkle authentication proof for a given wallet
    pub async fn add_wallet_merkle_proof(
        &self,
        wallet_id: &WalletIdentifier,
        merkle_proof: WalletAuthenticationPath,
    ) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet.write().await.merkle_proof = Some(merkle_proof)
        }
    }

    /// Merge metadata for a given wallet into the local wallet state
    pub async fn merge_metadata(&self, wallet_id: &WalletIdentifier, metadata: &WalletMetadata) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            if wallet
                .read()
                .await
                .metadata
                .replicas
                .is_superset(&metadata.replicas)
            {
                return;
            }

            // Acquire a write lock only if we are missing replicas
            let mut locked_wallet = wallet.write().await;
            locked_wallet.metadata.replicas.extend(&metadata.replicas);
        }
    }

    /// Expire peers as replicas of each wallet we know about
    ///
    /// This method is called when a cluster peer is determined to have failed; we should
    /// update the replication state and take any steps necessary to get the wallet replicated
    /// on a safe number of peers
    pub async fn remove_peer_replicas(&self, peer: &WrappedPeerId) {
        for (_, wallet) in self.wallet_map.iter() {
            let mut locked_wallet = wallet.write().await;
            locked_wallet.metadata.replicas.remove(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use num_bigint::BigUint;
    use rand_core::OsRng;

    use super::PrivateKeyChain;

    /// Test serialization/deserialization of a PrivateKeyChain
    #[test]
    fn test_private_keychain_serde() {
        let mut rng = OsRng {};

        // Test with root specified
        let keychain = PrivateKeyChain {
            sk_root: Some((&BigUint::from(0u8)).into()),
            sk_match: Scalar::random(&mut rng).into(),
        };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);

        // Test with no root specified
        let keychain = PrivateKeyChain {
            sk_root: None,
            sk_match: Scalar::random(&mut rng).into(),
        };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);
    }
}
