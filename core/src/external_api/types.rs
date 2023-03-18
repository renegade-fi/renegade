//! Defines API type definitions used in request/response messages

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

use crate::state::{wallet::Wallet as IndexedWallet, NetworkOrderState, OrderIdentifier};

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
    fn from(wallet: IndexedWallet) -> Self {
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

        let key_chain = KeyChain {
            public_keys: PublicKeys {
                pk_root: scalar_to_biguint(&wallet.public_keys.pk_root),
                pk_match: scalar_to_biguint(&wallet.public_keys.pk_match),
                pk_settle: scalar_to_biguint(&wallet.public_keys.pk_settle),
                pk_view: scalar_to_biguint(&wallet.public_keys.pk_view),
            },
            secret_keys: SecretKeys {
                sk_root: wallet
                    .secret_keys
                    .sk_root
                    .map(|key| scalar_to_biguint(&key)),
                sk_match: scalar_to_biguint(&wallet.secret_keys.sk_match),
                sk_settle: scalar_to_biguint(&wallet.secret_keys.sk_settle),
                sk_view: scalar_to_biguint(&wallet.secret_keys.sk_view),
            },
        };

        Self {
            id: wallet.wallet_id,
            orders,
            balances,
            fees,
            key_chain,
            randomness: wallet.randomness,
        }
    }
}

/// The order type, represents a trader's intention in the pool
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Order {
    /// Identifier
    pub id: Uuid,
    /// The quote token mint
    pub quote_mint: BigUint,
    /// The base token mint
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

/// A fee, payable to the relayer that matches orders on behalf of a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fee {
    /// The public settle key of the fee recipient
    pub recipient_key: BigUint,
    /// The ERC-20 address of the token to pay for gas in
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

/// A keychain holds public and private keys that authorize various actions on a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyChain {
    /// The public keys in the wallet
    pub public_keys: PublicKeys,
    /// The secret keys in the wallet
    pub secret_keys: SecretKeys,
}

/// A set of public keys for a given wallet
///
/// See the docs (https://docs.renegade.fi/advanced-concepts/super-relayers#key-hierarchy)
/// for more information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeys {
    /// The public root key
    pub pk_root: BigUint,
    /// The public match key
    pub pk_match: BigUint,
    /// The public settle key
    pub pk_settle: BigUint,
    /// The public view key
    pub pk_view: BigUint,
}

/// The set of secret keys for a wallet
///
/// Note that `sk_root` may be unknown as a relayer that holds `sk_root` is said
/// to be in "super-relayer" mode, not all relayers are
///
/// See the docs (https://docs.renegade.fi/advanced-concepts/super-relayers#key-hierarchy)
/// for more information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKeys {
    /// The secret root key, non-super relayers will hold `None`
    pub sk_root: Option<BigUint>,
    /// The secret match key
    pub sk_match: BigUint,
    /// The secret settle key
    pub sk_settle: BigUint,
    /// The secret view key
    pub sk_view: BigUint,
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

// ------------------------------
// | P2P Network Info API Types |
// ------------------------------

/// The network topology
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    /// Identifier, e.g. "goerli"
    pub id: String,
    /// The list of clusters known to the local peer
    pub cluster: Vec<Cluster>,
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
