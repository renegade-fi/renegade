//! Defines API type definitions used in request/response messages

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::atomic::AtomicU32,
    time::{SystemTime, UNIX_EPOCH},
};

use circuits::{
    types::{
        balance::Balance as IndexedBalance,
        fee::Fee as IndexedFee,
        order::{Order as IndexedOrder, OrderSide},
    },
    zk_gadgets::fixed_point::FixedPoint,
};
use crypto::fields::scalar_to_biguint;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    external_api::{biguint_from_hex_string, biguint_to_hex_string},
    gossip::types::PeerInfo as IndexedPeerInfo,
    state::{
        wallet::{KeyChain, Wallet as IndexedWallet, WalletMetadata},
        NetworkOrder as IndexedNetworkOrder, NetworkOrderState, OrderIdentifier,
    },
};

/// The Goerli network identifier
const STARKNET_ALPHA_GOERLI: &str = "starknet-alpha-goerli";

// --------------------
// | Wallet API Types |
// --------------------

/// The wallet type, holds all balances, orders, fees, and randomness
/// for a trader
///
/// Also the unit of commitment in the state tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Identifier
    pub id: Uuid,
    /// The orders maintained by this wallet
    pub orders: Vec<Order>,
    /// The balances maintained by the wallet to cover orders
    pub balances: Vec<Balance>,
    /// The fees to cover match costs
    pub fees: Vec<Fee>,
    /// The keys that authenticate wallet access
    pub key_chain: KeyChain,
    /// The wallet randomness used to blind commitments
    pub randomness: BigUint,
}

/// Conversion from a wallet that has been indexed in the global state to the
/// API type
impl From<IndexedWallet> for Wallet {
    fn from(mut wallet: IndexedWallet) -> Self {
        // Remove all default orders, balances, and fees from the wallet
        // These are used to pad the wallet to the size of the circuit, and are
        // not relevant to the client
        wallet.remove_default_elements();

        // Build API types from the indexed wallet
        let orders = wallet
            .orders
            .into_iter()
            .map(|order| order.into())
            .collect_vec();

        let balances = wallet
            .balances
            .into_iter()
            .map(|(_, balance)| balance.into())
            .collect_vec();

        let fees = wallet.fees.into_iter().map(|fee| fee.into()).collect_vec();

        Self {
            id: wallet.wallet_id,
            orders,
            balances,
            fees,
            key_chain: wallet.key_chain.clone(),
            randomness: wallet.randomness,
        }
    }
}

impl From<Wallet> for IndexedWallet {
    fn from(wallet: Wallet) -> Self {
        let orders = wallet
            .orders
            .into_iter()
            .map(|order| (Uuid::new_v4(), order.into()))
            .collect();
        let balances = wallet
            .balances
            .into_iter()
            .map(|balance| (balance.mint.clone(), balance.into()))
            .collect();
        let fees = wallet.fees.into_iter().map(|fee| fee.into()).collect();

        IndexedWallet {
            wallet_id: Uuid::new_v4(),
            orders,
            balances,
            fees,
            key_chain: wallet.key_chain,
            randomness: wallet.randomness,
            metadata: WalletMetadata::default(),
            proof_staleness: AtomicU32::new(0),
            merkle_proof: None,
        }
    }
}

/// The order type, represents a trader's intention in the pool
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Order {
    /// Identifier
    pub id: Uuid,
    /// The quote token mint
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The base token mint
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub base_mint: BigUint,
    /// The side of the market this order is on
    pub side: OrderSide,
    /// The type of order
    #[serde(rename = "type")]
    pub type_: OrderType,
    /// The limit price in the case that this is a limit order
    pub price: FixedPoint,
    /// The order size
    pub amount: BigUint,
    /// The timestamp this order was placed at
    pub timestamp: u64,
}

impl From<(OrderIdentifier, IndexedOrder)> for Order {
    fn from((order_id, order): (OrderIdentifier, IndexedOrder)) -> Self {
        Order {
            id: order_id,
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            type_: OrderType::Limit,
            price: order.price,
            amount: BigUint::from(order.amount),
            timestamp: order.timestamp,
        }
    }
}

impl From<Order> for IndexedOrder {
    fn from(order: Order) -> Self {
        IndexedOrder {
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            price: order.price,
            amount: order.amount.try_into().unwrap(),
            timestamp: order.timestamp,
        }
    }
}

/// The type of order, currently limit or midpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OrderType {
    /// A market-midpoint pegged order
    Midpoint = 0,
    /// A limit order with specified price attached
    Limit,
}

impl Default for OrderType {
    fn default() -> Self {
        OrderType::Midpoint
    }
}

/// A balance that a wallet holds of some asset
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Balance {
    /// The ERC-20 address of the token
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount held in the balance
    pub amount: BigUint,
}

impl From<IndexedBalance> for Balance {
    fn from(balance: IndexedBalance) -> Self {
        Balance {
            mint: balance.mint,
            amount: BigUint::from(balance.amount),
        }
    }
}

impl From<Balance> for IndexedBalance {
    fn from(balance: Balance) -> Self {
        IndexedBalance {
            mint: balance.mint,
            amount: balance.amount.try_into().unwrap(),
        }
    }
}

/// A fee, payable to the relayer that matches orders on behalf of a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fee {
    /// The public settle key of the fee recipient
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub recipient_key: BigUint,
    /// The ERC-20 address of the token to pay for gas in
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub gas_addr: BigUint,
    /// The amount of the gas token to pay out covering transaction fees
    pub gas_amount: BigUint,
    /// The fee that the executing relayer may take off the sold asset
    pub percentage_fee: FixedPoint,
}

impl From<IndexedFee> for Fee {
    fn from(fee: IndexedFee) -> Self {
        Fee {
            recipient_key: fee.settle_key,
            gas_addr: fee.gas_addr,
            gas_amount: BigUint::from(fee.gas_token_amount),
            percentage_fee: fee.percentage_fee,
        }
    }
}

impl From<Fee> for IndexedFee {
    fn from(fee: Fee) -> Self {
        IndexedFee {
            settle_key: fee.recipient_key,
            gas_addr: fee.gas_addr,
            gas_token_amount: fee.gas_amount.try_into().unwrap(),
            percentage_fee: fee.percentage_fee,
        }
    }
}

// ------------------------
// | Order Book API Types |
// ------------------------

/// The order book known to the local node, consisting of all opaque
/// network orders being shopped around by peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderBook {
    /// The list of known orders
    pub orders: Vec<NetworkOrder>,
}

/// An opaque order known to the local peer only by a few opaque identifiers
/// possibly owned and known in the clear by the local peer as well
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOrder {
    /// Identifier
    pub id: Uuid,
    /// The match nullifier on the wallet managing this order
    pub match_nullifier: BigUint,
    /// Whether this order is managed by the local cluster
    pub local: bool,
    /// The cluster that manages this order
    pub cluster: String,
    /// The state of the order in the network
    pub state: NetworkOrderState,
    /// The timestamp that this order was first received at
    pub timestamp: u64,
}

impl From<IndexedNetworkOrder> for NetworkOrder {
    fn from(order: IndexedNetworkOrder) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        NetworkOrder {
            id: order.id,
            match_nullifier: scalar_to_biguint(&order.match_nullifier),
            local: order.local,
            cluster: order.cluster.to_string(),
            state: order.state,
            // TODO: Replace this with the time the order was received
            timestamp: now,
        }
    }
}

// ------------------------------
// | P2P Network Info API Types |
// ------------------------------

/// The network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    /// Identifier, e.g. "goerli"
    pub id: String,
    /// The list of clusters known to the local peer
    pub clusters: Vec<Cluster>,
}

/// Cast from a map of cluster ID to peer list to the `Cluster` API type
impl From<HashMap<String, Vec<Peer>>> for Network {
    fn from(cluster_membership: HashMap<String, Vec<Peer>>) -> Self {
        let mut clusters = Vec::with_capacity(cluster_membership.len());
        for (cluster_id, peers) in cluster_membership.into_iter() {
            clusters.push(Cluster {
                id: cluster_id,
                peers,
            });
        }

        Self {
            // TODO: Make this not a constant
            id: STARKNET_ALPHA_GOERLI.to_string(),
            clusters,
        }
    }
}

/// A cluster of peers, in the security model a cluster is assumed to be controlled
/// by a single actor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cluster {
    /// Identifier
    pub id: String,
    /// The list of peers known to be members of the cluster
    pub peers: Vec<Peer>,
}

/// A peer in the network known to the local node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    /// Identifier
    pub id: String,
    /// The ID of the cluster this peer belongs to
    pub cluster_id: String,
    /// The dialable, libp2p address of the peer
    pub addr: String,
}

impl From<IndexedPeerInfo> for Peer {
    fn from(peer_info: IndexedPeerInfo) -> Self {
        Self {
            id: peer_info.get_peer_id().to_string(),
            cluster_id: peer_info.get_cluster_id().to_string(),
            addr: peer_info.get_addr().to_string(),
        }
    }
}
