//! Defines API type definitions used in request/response messages

use std::{collections::HashMap, convert::TryInto, sync::atomic::Ordering};

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_string};
use circuit_types::{
    balance::Balance,
    fee::Fee,
    fixed_point::FixedPoint,
    keychain::{PublicIdentificationKey, PublicKeyChain, SecretIdentificationKey},
    order::{Order, OrderSide},
    traits::BaseType,
    SizedWalletShare,
};
use common::types::{
    gossip::PeerInfo as IndexedPeerInfo,
    network_order::{NetworkOrder, NetworkOrderState},
    wallet::{KeyChain, OrderIdentifier, PrivateKeyChain, Wallet, WalletMetadata},
};
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{Deserialize, Serialize};
use util::hex::{
    nonnative_scalar_from_hex_string, nonnative_scalar_to_hex_string,
    public_sign_key_from_hex_string, public_sign_key_to_hex_string, scalar_from_hex_string,
    scalar_to_hex_string,
};
use uuid::Uuid;

// --------------------
// | Wallet API Types |
// --------------------

/// The wallet type, holds all balances, orders, fees, and randomness
/// for a trader
///
/// Also the unit of commitment in the state tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiWallet {
    /// Identifier
    pub id: Uuid,
    /// The orders maintained by this wallet
    pub orders: Vec<ApiOrder>,
    /// The balances maintained by the wallet to cover orders
    pub balances: Vec<ApiBalance>,
    /// The fees to cover match costs
    pub fees: Vec<ApiFee>,
    /// The keys that authenticate wallet access
    pub key_chain: ApiKeychain,
    /// The public secret shares of the wallet
    pub blinded_public_shares: Vec<BigUint>,
    /// The private secret shares of the wallet
    pub private_shares: Vec<BigUint>,
    /// The wallet blinder, used to blind wallet secret shares
    pub blinder: BigUint,
    /// The state of update lock of the wallet, used to protect against
    /// concurrent updates to the wallet
    #[serde(default)]
    pub update_locked: bool,
}

/// Conversion from a wallet that has been indexed in the global state to the
/// API type
impl From<Wallet> for ApiWallet {
    fn from(mut wallet: Wallet) -> Self {
        // Remove all default orders, balances, and fees from the wallet
        // These are used to pad the wallet to the size of the circuit, and are
        // not relevant to the client
        wallet.remove_default_elements();

        // Build API types from the indexed wallet
        let orders = wallet.orders.into_iter().map(|order| order.into()).collect_vec();
        let balances = wallet.balances.into_values().map(|balance| balance.into()).collect_vec();
        let fees = wallet.fees.into_iter().map(|fee| fee.into()).collect_vec();

        // Serialize the shares then convert all values to BigUint
        let blinded_public_shares =
            wallet.blinded_public_shares.to_scalars().iter().map(scalar_to_biguint).collect_vec();
        let private_shares =
            wallet.private_shares.to_scalars().iter().map(scalar_to_biguint).collect_vec();

        Self {
            id: wallet.wallet_id,
            orders,
            balances,
            fees,
            key_chain: wallet.key_chain.into(),
            blinded_public_shares,
            private_shares,
            blinder: scalar_to_biguint(&wallet.blinder),
            update_locked: wallet.update_locked.load(Ordering::Relaxed),
        }
    }
}

impl TryFrom<ApiWallet> for Wallet {
    type Error = String;

    fn try_from(wallet: ApiWallet) -> Result<Self, Self::Error> {
        let orders =
            wallet.orders.into_iter().map(|order| (Uuid::new_v4(), order.into())).collect();
        let balances = wallet
            .balances
            .into_iter()
            .map(|balance| (balance.mint.clone(), balance.into()))
            .collect();
        let fees = wallet.fees.into_iter().map(|fee| fee.into()).collect();

        // Deserialize the shares to scalar then re-structure into WalletSecretShare
        let blinded_public_shares = SizedWalletShare::from_scalars(
            &mut wallet.blinded_public_shares.iter().map(biguint_to_scalar),
        );
        let private_shares = SizedWalletShare::from_scalars(
            &mut wallet.private_shares.iter().map(biguint_to_scalar),
        );

        Ok(Wallet {
            wallet_id: Uuid::new_v4(),
            orders,
            balances,
            fees,
            key_chain: wallet.key_chain.try_into()?,
            blinder: biguint_to_scalar(&wallet.blinder),
            metadata: WalletMetadata::default(),
            blinded_public_shares,
            private_shares,
            merkle_proof: None,
            merkle_staleness: Default::default(),
            update_locked: Default::default(),
        })
    }
}

/// The order type, represents a trader's intention in the pool
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApiOrder {
    /// Identifier
    pub id: Uuid,
    /// The quote token mint
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The base token mint
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub base_mint: BigUint,
    /// The side of the market this order is on
    pub side: OrderSide,
    /// The type of order
    #[serde(rename = "type")]
    pub type_: ApiOrderType,
    /// The worse case price that the order may be executed at
    ///
    /// For buy side orders this is a maximum price, for sell side orders
    /// this is a minimum price
    pub worst_case_price: FixedPoint,
    /// The order size
    pub amount: BigUint,
    /// The timestamp this order was placed at
    pub timestamp: u64,
}

impl From<(OrderIdentifier, Order)> for ApiOrder {
    fn from((order_id, order): (OrderIdentifier, Order)) -> Self {
        ApiOrder {
            id: order_id,
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            type_: ApiOrderType::Midpoint,
            worst_case_price: order.worst_case_price,
            amount: BigUint::from(order.amount),
            timestamp: order.timestamp,
        }
    }
}

impl From<ApiOrder> for Order {
    fn from(order: ApiOrder) -> Self {
        Order {
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            worst_case_price: order.worst_case_price,
            amount: order.amount.try_into().unwrap(),
            timestamp: order.timestamp,
        }
    }
}

/// The type of order, currently limit or midpoint
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub enum ApiOrderType {
    /// A market-midpoint pegged order
    #[default]
    Midpoint = 0,
    /// A limit order with specified price attached
    Limit,
}

/// A balance that a wallet holds of some asset
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApiBalance {
    /// The ERC-20 address of the token
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub mint: BigUint,
    /// The amount held in the balance
    pub amount: BigUint,
}

impl From<Balance> for ApiBalance {
    fn from(balance: Balance) -> Self {
        ApiBalance { mint: balance.mint, amount: BigUint::from(balance.amount) }
    }
}

impl From<ApiBalance> for Balance {
    fn from(balance: ApiBalance) -> Self {
        Balance { mint: balance.mint, amount: balance.amount.try_into().unwrap() }
    }
}

/// A fee, payable to the relayer that matches orders on behalf of a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiFee {
    /// The public settle key of the fee recipient
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub recipient_key: BigUint,
    /// The ERC-20 address of the token to pay for gas in
    #[serde(
        serialize_with = "serialize_biguint_to_hex_string",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub gas_addr: BigUint,
    /// The amount of the gas token to pay out covering transaction fees
    pub gas_amount: BigUint,
    /// The fee that the executing relayer may take off the sold asset
    pub percentage_fee: FixedPoint,
}

impl From<Fee> for ApiFee {
    fn from(fee: Fee) -> Self {
        ApiFee {
            recipient_key: fee.settle_key,
            gas_addr: fee.gas_addr,
            gas_amount: BigUint::from(fee.gas_token_amount),
            percentage_fee: fee.percentage_fee,
        }
    }
}

impl From<ApiFee> for Fee {
    fn from(fee: ApiFee) -> Self {
        Fee {
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
    pub orders: Vec<ApiNetworkOrder>,
}

/// An opaque order known to the local peer only by a few opaque identifiers
/// possibly owned and known in the clear by the local peer as well
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiNetworkOrder {
    /// Identifier
    pub id: Uuid,
    /// The nullifier of the containing wallet's public secret shares
    pub public_share_nullifier: BigUint,
    /// Whether this order is managed by the local cluster
    pub local: bool,
    /// The cluster that manages this order
    pub cluster: String,
    /// The state of the order in the network
    pub state: NetworkOrderState,
    /// The timestamp that this order was first received at
    pub timestamp: u64,
}

impl From<NetworkOrder> for ApiNetworkOrder {
    fn from(order: NetworkOrder) -> Self {
        ApiNetworkOrder {
            id: order.id,
            public_share_nullifier: scalar_to_biguint(&order.public_share_nullifier),
            local: order.local,
            cluster: order.cluster.to_string(),
            state: order.state,
            timestamp: order.timestamp,
        }
    }
}

/// A keychain API type that maintains all keys as hex strings, conversion to
/// the runtime keychain type involves deserializing these keys into their
/// native types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeychain {
    /// The public keychain
    pub public_keys: ApiPublicKeychain,
    /// The private keychain
    pub private_keys: ApiPrivateKeychain,
}

/// A public keychain for the API wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPublicKeychain {
    /// The public root key of the wallet
    pub pk_root: String,
    /// The public match key of the wallet
    pub pk_match: String,
}

/// A private keychain for the API wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPrivateKeychain {
    /// The private root key of the wallet
    pub sk_root: Option<String>,
    /// The private match key of the wallet
    pub sk_match: String,
}

impl From<KeyChain> for ApiKeychain {
    fn from(keys: KeyChain) -> Self {
        Self {
            public_keys: ApiPublicKeychain {
                pk_root: public_sign_key_to_hex_string(&keys.public_keys.pk_root),
                pk_match: scalar_to_hex_string(&keys.public_keys.pk_match.key),
            },
            private_keys: ApiPrivateKeychain {
                sk_root: keys.secret_keys.sk_root.map(|k| nonnative_scalar_to_hex_string(&k)),
                sk_match: scalar_to_hex_string(&keys.secret_keys.sk_match.key),
            },
        }
    }
}

impl TryFrom<ApiKeychain> for KeyChain {
    type Error = String;

    fn try_from(keys: ApiKeychain) -> Result<Self, Self::Error> {
        Ok(KeyChain {
            public_keys: PublicKeyChain {
                pk_root: public_sign_key_from_hex_string(&keys.public_keys.pk_root)?,
                pk_match: PublicIdentificationKey {
                    key: scalar_from_hex_string(&keys.public_keys.pk_match)?,
                },
            },
            secret_keys: PrivateKeyChain {
                sk_root: keys
                    .private_keys
                    .sk_root
                    .map(|k| nonnative_scalar_from_hex_string(&k))
                    .transpose()?,
                sk_match: SecretIdentificationKey {
                    key: scalar_from_hex_string(&keys.private_keys.sk_match)?,
                },
            },
        })
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
            clusters.push(Cluster { id: cluster_id, peers });
        }

        Self {
            // TODO: Make this not a constant
            id: "goerli".to_string(),
            clusters,
        }
    }
}

/// A cluster of peers, in the security model a cluster is assumed to be
/// controlled by a single actor
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
