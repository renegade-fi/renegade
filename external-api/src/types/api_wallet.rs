//! API types for wallet information

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    keychain::{PublicIdentificationKey, PublicKeyChain, SecretIdentificationKey},
    order::{Order, OrderSide},
    traits::BaseType,
    Amount, SizedWalletShare,
};
use common::types::wallet::{KeyChain, OrderIdentifier, PrivateKeyChain, Wallet, WalletIdentifier};
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{Deserialize, Serialize};
use util::hex::{
    jubjub_from_hex_string, jubjub_to_hex_string, nonnative_scalar_from_hex_string,
    nonnative_scalar_to_hex_string, public_sign_key_from_hex_string, public_sign_key_to_hex_string,
    scalar_from_hex_string, scalar_to_hex_string,
};
use uuid::Uuid;

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_addr};

/// The wallet type, holds all balances, orders, metadata, and randomness
/// for a trader
///
/// Also the unit of commitment in the state tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiWallet {
    /// Identifier
    pub id: WalletIdentifier,
    /// The orders maintained by this wallet
    pub orders: Vec<ApiOrder>,
    /// The balances maintained by the wallet to cover orders
    pub balances: Vec<Balance>,
    /// The keys that authenticate wallet access
    pub key_chain: ApiKeychain,
    /// The managing cluster's public key
    ///
    /// The public encryption key of the cluster that may collect relayer fees
    /// on this wallet
    pub managing_cluster: String,
    /// The take rate at which the managing cluster may collect relayer fees on
    /// a match
    pub match_fee: FixedPoint,
    /// The public secret shares of the wallet
    pub blinded_public_shares: Vec<BigUint>,
    /// The private secret shares of the wallet
    pub private_shares: Vec<BigUint>,
    /// The wallet blinder, used to blind wallet secret shares
    pub blinder: BigUint,
}

/// Conversion from a wallet that has been indexed in the global state to the
/// API type
impl From<Wallet> for ApiWallet {
    fn from(wallet: Wallet) -> Self {
        // Build API types from the indexed wallet
        let orders = wallet.orders.into_iter().map(|order| order.into()).collect_vec();
        let balances = wallet.balances.into_values().collect_vec();

        // Serialize the shares then convert all values to BigUint
        let blinded_public_shares =
            wallet.blinded_public_shares.to_scalars().iter().map(scalar_to_biguint).collect_vec();
        let private_shares =
            wallet.private_shares.to_scalars().iter().map(scalar_to_biguint).collect_vec();

        Self {
            id: wallet.wallet_id,
            orders,
            balances,
            key_chain: wallet.key_chain.into(),
            managing_cluster: jubjub_to_hex_string(&wallet.managing_cluster),
            match_fee: wallet.match_fee,
            blinded_public_shares,
            private_shares,
            blinder: scalar_to_biguint(&wallet.blinder),
        }
    }
}

impl TryFrom<ApiWallet> for Wallet {
    type Error = String;

    fn try_from(wallet: ApiWallet) -> Result<Self, Self::Error> {
        let orders = wallet.orders.into_iter().map(|order| (order.id, order.into())).collect();
        let balances =
            wallet.balances.into_iter().map(|balance| (balance.mint.clone(), balance)).collect();

        // Deserialize the shares to scalar then re-structure into WalletSecretShare
        let blinded_public_shares = SizedWalletShare::from_scalars(
            &mut wallet.blinded_public_shares.iter().map(biguint_to_scalar),
        );
        let private_shares = SizedWalletShare::from_scalars(
            &mut wallet.private_shares.iter().map(biguint_to_scalar),
        );

        let managing_cluster = jubjub_from_hex_string(&wallet.managing_cluster)?;

        Ok(Wallet {
            wallet_id: wallet.id,
            orders,
            balances,
            key_chain: wallet.key_chain.try_into()?,
            match_fee: wallet.match_fee,
            managing_cluster,
            blinder: biguint_to_scalar(&wallet.blinder),
            blinded_public_shares,
            private_shares,
            merkle_proof: None,
            merkle_staleness: Default::default(),
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
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The base token mint
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
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
    pub amount: Amount,
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
            amount: order.amount,
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
            amount: order.amount,
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
            public_keys: PublicKeyChain::new(
                public_sign_key_from_hex_string(&keys.public_keys.pk_root)?,
                PublicIdentificationKey {
                    key: scalar_from_hex_string(&keys.public_keys.pk_match)?,
                },
            ),
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
