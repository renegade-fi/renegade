//! Groups state primitives for indexing and tracking wallet information

use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fmt::{Display, Formatter, Result as FmtResult},
    iter,
    sync::RwLockReadGuard,
};

use circuits::{
    native_helpers::compute_wallet_commitment,
    types::{
        balance::Balance,
        fee::Fee,
        keychain::{KeyChain, NUM_KEYS},
        order::{Order, OrderSide},
        wallet::{Wallet as CircuitWallet, WalletCommitment},
    },
};
use crypto::fields::{biguint_to_scalar, prime_field_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{
    de::{Error as SerdeErr, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Serialize,
};
use termion::color;
use uuid::Uuid;

use crate::{gossip::types::WrappedPeerId, MAX_BALANCES, MAX_FEES, MAX_ORDERS};

use super::{new_shared, orderbook::OrderIdentifier, Shared};

/// A type that attaches default size parameters to a circuit allocated wallet
type SizedCircuitWallet = CircuitWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// An error message to panic with when a wallet lock is poisoned
const ERR_WALLET_POISONED: &str = "wallet lock poisoned";

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

/// Represents a wallet managed by the local relayer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// The identifier used to index the wallet
    pub wallet_id: WalletIdentifier,
    /// A list of orders in this wallet
    pub orders: HashMap<OrderIdentifier, Order>,
    /// A mapping of mint (u64) to Balance information
    /// TODO: Key by BigUint to adequately represent mints
    pub balances: HashMap<u64, Balance>,
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
}

/// Metadata relevant to the wallet's network state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// The peers which are believed by the local node to be replicating a given wallet
    pub replicas: HashSet<WrappedPeerId>,
}

/// An abstraction over a set of wallets that indexes wallet and de-normalizes
/// their data
#[derive(Clone, Debug)]
pub struct WalletIndex {
    /// The peer_id of the local node
    peer_id: WrappedPeerId,
    /// A mapping from wallet ID to wallet information
    wallet_map: HashMap<Uuid, Shared<Wallet>>,
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
    pub fn read_wallet(&self, wallet_id: &Uuid) -> Option<RwLockReadGuard<Wallet>> {
        self.wallet_map
            .get(wallet_id)
            .map(|wallet| wallet.read().expect(ERR_WALLET_POISONED))
    }

    // -----------
    // | Getters |
    // -----------

    /// Get the wallet that an order is allocated in
    pub fn get_wallet_for_order(&self, order_id: &OrderIdentifier) -> Option<WalletIdentifier> {
        self.order_to_wallet.get(order_id).cloned()
    }

    /// Returns a list of all wallets
    pub fn get_all_wallets(&self) -> Vec<Wallet> {
        self.wallet_map
            .values()
            .map(|wallet| wallet.read().expect(ERR_WALLET_POISONED).clone())
            .collect_vec()
    }

    /// Returns a mapping from wallet ID to the wallet's metadata
    ///
    /// Used to serialize into the handshake response
    pub fn get_metadata_map(&self) -> HashMap<WalletIdentifier, WalletMetadata> {
        let mut res = HashMap::new();
        for (id, wallet) in self.wallet_map.iter() {
            res.insert(
                *id,
                wallet.read().expect(ERR_WALLET_POISONED).metadata.clone(),
            );
        }

        res
    }

    /// Get a balance and a fee for a given order in a given wallet
    ///
    /// Returns a 4-tuple of (order, balance, fee, fee_balance) where fee_balance is the
    /// balance used to cover the payable fee
    pub fn get_order_balance_and_fee(
        &self,
        wallet_id: &Uuid,
        order_id: &OrderIdentifier,
    ) -> Option<(Order, Balance, Fee, Balance)> {
        let locked_wallet = self.read_wallet(wallet_id)?;
        let order = locked_wallet.orders.get(order_id)?;

        // The mint the local party will be spending if the order is matched
        let order_mint = match order.side {
            OrderSide::Buy => order.quote_mint,
            OrderSide::Sell => order.base_mint,
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
        let fee_balance = locked_wallet
            .balances
            .get(&fee.gas_addr.clone().try_into().unwrap())?;
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
        self.wallet_map.insert(wallet.wallet_id, new_shared(wallet));
    }

    /// Add a given peer as a replica of a wallet
    pub fn add_replica(&self, wallet_id: &WalletIdentifier, peer_id: WrappedPeerId) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            wallet
                .write()
                .expect(ERR_WALLET_POISONED)
                .metadata
                .replicas
                .insert(peer_id);
        }
    }

    /// Merge metadata for a given wallet into the local wallet state
    pub fn merge_metadata(&self, wallet_id: &WalletIdentifier, metadata: &WalletMetadata) {
        if let Some(wallet) = self.wallet_map.get(wallet_id) {
            if wallet
                .read()
                .expect(ERR_WALLET_POISONED)
                .metadata
                .replicas
                .is_superset(&metadata.replicas)
            {
                return;
            }

            // Acquire a write lock only if we are missing replicas
            let mut locked_wallet = wallet.write().expect(ERR_WALLET_POISONED);
            locked_wallet.metadata.replicas.extend(&metadata.replicas);
        }
    }

    /// Expire peers as replicas of each wallet we know about
    ///
    /// This method is called when a cluster peer is determined to have failed; we should
    /// update the replication state and take any steps necessary to get the wallet replicated
    /// on a safe number of peers
    pub fn remove_peer_replicas(&self, peer: &WrappedPeerId) {
        for (_, wallet) in self.wallet_map.iter() {
            let mut locked_wallet = wallet.write().expect("wallet lock poisoned");
            locked_wallet.metadata.replicas.remove(peer);
        }
    }
}

/// Display implementation for when the relayer is placed in Debug mode
impl Display for WalletIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Write a header
        f.write_fmt(format_args!(
            "\n\t{}Managed Wallets:{}\n",
            color::Fg(color::LightGreen),
            color::Fg(color::Reset)
        ))?;

        // Write each wallet into the debug
        for (wallet_id, wallet) in self.wallet_map.iter() {
            f.write_fmt(format_args!(
                "\t\t- {}{:?}:{} {{\n\t\t\t{}replicas{}: [\n",
                color::Fg(color::LightYellow),
                wallet_id,
                color::Fg(color::Reset),
                color::Fg(color::Blue),
                color::Fg(color::Reset),
            ))?;
            for replica in wallet.read().unwrap().metadata.replicas.iter() {
                f.write_fmt(format_args!("\t\t\t\t{}\n", replica.0))?;
            }

            f.write_str("\t\t\t]\n\t\t}")?;
        }

        Ok(())
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
