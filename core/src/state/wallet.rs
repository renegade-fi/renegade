//! Groups state primitives for indexing and tracking wallet information

use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fmt::{Formatter, Result as FmtResult},
    iter,
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
};

use circuits::{
    native_helpers::{
        compute_poseidon_hash, compute_wallet_commitment, compute_wallet_match_nullifier,
    },
    types::{
        balance::Balance,
        fee::Fee,
        keychain::{KeyChain, NUM_KEYS},
        order::{Order, OrderSide},
        wallet::{Nullifier, Wallet as CircuitWallet, WalletCommitment},
    },
    zk_gadgets::merkle::MerkleOpening,
};
use crypto::fields::{biguint_to_scalar, prime_field_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use futures::{stream::iter as to_stream, StreamExt};
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{
    de::{Error as SerdeErr, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

use crate::{
    gossip::types::WrappedPeerId, MAX_BALANCES, MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT,
    MERKLE_ROOT_HISTORY_LENGTH,
};

use super::{new_async_shared, orderbook::OrderIdentifier, AsyncShared, MerkleTreeCoords};

/// The staleness factor; the ratio of the root history that has elapsed before a new proof of
/// `VALID COMMITMENTS` is required for an order
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyChain {
    /// Optionally the relayer holds sk_root, in which case the relayer has
    /// heightened permissions than the standard case
    ///
    /// We call such a relayer a "super relayer"
    pub sk_root: Option<Scalar>,
    /// The match private key, authorizes the relayer to match orders for the wallet
    pub sk_match: Scalar,
    /// The settle private key, authorizes the relayer to settle matches for the wallet
    pub sk_settle: Scalar,
    /// The view private key, allows the relayer to decrypt wallet state on chain
    pub sk_view: Scalar,
}

/// Custom serialization/deserialization for PrivateKeyChain, allowing us to serialize and
/// deserialize the keys as BigUints rather than Dalek Scalars
///
/// The BigUint representation is cleaner and more interpretable
impl Serialize for PrivateKeyChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let sk_root_bigint = self.sk_root.map(|scalar| scalar_to_biguint(&scalar));

        // Serialize as a sequence of BigUints
        let mut seq = serializer.serialize_seq(Some(NUM_KEYS))?;
        seq.serialize_element(&sk_root_bigint)?;
        seq.serialize_element(&scalar_to_biguint(&self.sk_match))?;
        seq.serialize_element(&scalar_to_biguint(&self.sk_settle))?;
        seq.serialize_element(&scalar_to_biguint(&self.sk_view))?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for PrivateKeyChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(PrivateKeyChainVisitor)
    }
}

/// A serde visitor implementation for PrivateKeyChain
struct PrivateKeyChainVisitor;
impl<'de> Visitor<'de> for PrivateKeyChainVisitor {
    type Value = PrivateKeyChain;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "expecting sequence of {} BigUint values",
            NUM_KEYS
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let sk_root: Option<BigUint> = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("sk_root not found in serialized value"))?;
        let sk_match: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("sk_match not found in serialized value"))?;
        let sk_settle: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("sk_settle not found in serialized value"))?;
        let sk_view: BigUint = seq
            .next_element()?
            .ok_or_else(|| SerdeErr::custom("sk_view not found in serialized value"))?;

        Ok(Self::Value {
            sk_root: sk_root.map(|val| biguint_to_scalar(&val)),
            sk_match: biguint_to_scalar(&sk_match),
            sk_settle: biguint_to_scalar(&sk_settle),
            sk_view: biguint_to_scalar(&sk_view),
        })
    }
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
impl From<MerkleAuthenticationPath> for MerkleOpening {
    fn from(native_path: MerkleAuthenticationPath) -> Self {
        // The path conversion is simply the first `MERKLE_HEIGHT` bits of
        // the leaf index
        let path_indices = (0..MERKLE_HEIGHT)
            .map(|bit| native_path.leaf_index.bit(bit as u64))
            .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
            .collect_vec();

        MerkleOpening {
            elems: native_path.path_siblings.to_vec(),
            indices: path_indices,
        }
    }
}

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
    /// A list of the public keys in the wallet
    pub public_keys: KeyChain,
    /// A list of the secret keys the relayer has access to
    pub secret_keys: PrivateKeyChain,
    /// The wallet randomness
    pub randomness: BigUint,
    /// Wallet metadata; replicas, trusted peers, etc
    pub metadata: WalletMetadata,
    /// The authentication path for the wallet
    #[serde(default)]
    pub merkle_proof: Option<MerkleAuthenticationPath>,
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
            public_keys: self.public_keys,
            secret_keys: self.secret_keys,
            randomness: self.randomness.clone(),
            metadata: self.metadata.clone(),
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
        let bigint_key = BigUint::from_str(&k).map_err(|err| SerdeErr::custom(err.to_string()))?;
        bigint_keyed_map.insert(bigint_key, balance);
    }

    Ok(bigint_keyed_map)
}

impl From<Wallet> for SizedCircuitWallet {
    fn from(wallet: Wallet) -> Self {
        // Pad the balances, orders, and fees to the size the wallet circuitry expects
        let padded_balances: [Balance; MAX_BALANCES] = wallet
            .balances
            .values()
            .cloned()
            .chain(iter::repeat(Balance::default()))
            .take(MAX_BALANCES)
            .collect_vec()
            .try_into()
            .unwrap();
        let padded_orders: [Order; MAX_ORDERS] = wallet
            .orders
            .values()
            .cloned()
            .chain(iter::repeat(Order::default()))
            .take(MAX_ORDERS)
            .collect_vec()
            .try_into()
            .unwrap();
        let padded_fees: [Fee; MAX_FEES] = wallet
            .fees
            .iter()
            .cloned()
            .chain(iter::repeat(Fee::default()))
            .take(MAX_FEES)
            .collect_vec()
            .try_into()
            .unwrap();

        CircuitWallet {
            balances: padded_balances,
            orders: padded_orders,
            fees: padded_fees,
            keys: wallet.public_keys,
            randomness: biguint_to_scalar(&wallet.randomness),
        }
    }
}

impl Wallet {
    /// Computes the commitment to the wallet; this commitment is used as the state
    /// entry for the wallet as a leaf in the Merkle tree
    pub fn get_commitment(&self) -> WalletCommitment {
        let circuit_wallet: SizedCircuitWallet = self.clone().into();
        prime_field_to_scalar(&compute_wallet_commitment(&circuit_wallet))
    }

    /// Computes the match nullifier of the wallet
    pub fn get_match_nullifier(&self) -> Nullifier {
        let circuit_wallet: SizedCircuitWallet = self.clone().into();
        prime_field_to_scalar(&compute_wallet_match_nullifier(
            &circuit_wallet,
            compute_wallet_commitment(&circuit_wallet),
        ))
    }

    /// Decides whether the wallet's orders need new commitment proofs
    ///
    /// When the Merkle roots get too stale, we need to re-prove the
    /// `VALID COMMITMENTS` entry for each order in the wallet on a fresh
    /// root that the contract will have stored when matches occur
    ///
    /// This method, although simple, is written abstractly to allow us to change
    /// the logic that decides this down the line
    pub fn needs_new_commitment_proof(&self) -> bool {
        let staleness = self.proof_staleness.load(Ordering::Relaxed);
        staleness > *STALENESS_THRESHOLD
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

/// An abstraction over a set of wallets that indexes wallet and de-normalizes
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

    /// Get a balance and a fee for a given order in a given wallet
    ///
    /// Returns a 4-tuple of (order, balance, fee, fee_balance) where fee_balance is the
    /// balance used to cover the payable fee
    pub async fn get_order_balance_and_fee(
        &self,
        wallet_id: &Uuid,
        order_id: &OrderIdentifier,
    ) -> Option<(Order, Balance, Fee, Balance)> {
        let locked_wallet = self.read_wallet(wallet_id).await?;
        let order = locked_wallet.orders.get(order_id)?;

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
        let balance = locked_wallet.balances.get(&order_mint)?;
        if balance.amount < order_amount {
            return None;
        }

        let fee = locked_wallet.fees.get(0 /* index */)?;
        let fee_balance = locked_wallet.balances.get(&fee.gas_addr.clone())?;
        if fee_balance.amount < fee.gas_token_amount {
            return None;
        }

        Some((
            order.clone(),
            balance.clone(),
            fee.clone(),
            fee_balance.clone(),
        ))
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
        merkle_proof: MerkleAuthenticationPath,
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
    use rand_core::OsRng;

    use super::PrivateKeyChain;

    /// Test serialization/deserialization of a PrivateKeyChain
    #[test]
    fn test_private_keychain_serde() {
        let mut rng = OsRng {};

        // Test with root specified
        let keychain = PrivateKeyChain {
            sk_root: Some(Scalar::random(&mut rng)),
            sk_match: Scalar::random(&mut rng),
            sk_settle: Scalar::random(&mut rng),
            sk_view: Scalar::random(&mut rng),
        };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);

        // Test with no root specified
        let keychain = PrivateKeyChain {
            sk_root: None,
            sk_match: Scalar::random(&mut rng),
            sk_settle: Scalar::random(&mut rng),
            sk_view: Scalar::random(&mut rng),
        };
        let serialized = serde_json::to_string(&keychain).unwrap();
        let deserialized: PrivateKeyChain = serde_json::from_str(&serialized).unwrap();
        assert_eq!(keychain, deserialized);
    }
}
