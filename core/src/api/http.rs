//! Groups API definitions for the externally facing HTTP API

use circuits::types::{fee::Fee, keychain::KeyChain};
use crypto::fields::biguint_to_scalar;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    gossip::types::WrappedPeerId,
    price_reporter::{
        exchanges::{Exchange, ExchangeConnectionState},
        reporter::PriceReporterState,
        tokens::Token,
    },
};

// ------------------------------------
// | Generic Request Response Formats |
// ------------------------------------

/// A ping request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingRequest;

/// A ping response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResponse {
    /// The timestamp when the response is sent
    pub timestamp: u128,
}

// ----------------------------------------------
// | Wallet Operations Request Response Formats |
// ----------------------------------------------

/// A keychain type that allows us to serialize/deserialize as a BigUint
/// rather than as a Scalar. The BigUint type has a more stable serde impl
/// and is generally more convenient
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyChainAPIType {
    /// The public root key of the wallet
    pub pk_root: BigUint,
    /// The public match key of the wallet
    pub pk_match: BigUint,
    /// The public settle key of the wallet
    pub pk_settle: BigUint,
    /// The public view key of the wallet
    pub pk_view: BigUint,
}

impl From<KeyChainAPIType> for KeyChain {
    fn from(keychain: KeyChainAPIType) -> Self {
        KeyChain {
            pk_root: biguint_to_scalar(&keychain.pk_root),
            pk_match: biguint_to_scalar(&keychain.pk_match),
            pk_settle: biguint_to_scalar(&keychain.pk_settle),
            pk_view: biguint_to_scalar(&keychain.pk_view),
        }
    }
}

/// The request type to create a new wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    /// A list of fees to initialize with
    pub fees: Vec<Fee>,
    /// A set of public keys to initialize the wallet with
    pub keys: KeyChainAPIType,
    /// A randomness value to seed the wallet with
    pub randomness: BigUint,
}

// --------------------------------------------
// | Price Reporting Request Response Formats |
// --------------------------------------------

/// A request to get the health of each exchange for a given token pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetExchangeHealthStatesRequest {
    /// The base token
    pub base_token: Token,
    /// The quote token
    pub quote_token: Token,
}

/// A response containing the health of each exchange
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetExchangeHealthStatesResponse {
    /// The PriceReporterState corresponding to the instantaneous median PriceReport
    pub median: PriceReporterState,
    /// The map of all ExchangeConnectionState corresponding to each individual exchange
    pub all_exchanges: HashMap<Exchange, ExchangeConnectionState>,
}

// -----------------------------------------
// | Cluster Info Request Response Formats |
// -----------------------------------------

/// A request to get the replicas of a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetReplicasRequest {
    /// The ID of the wallet requested
    pub wallet_id: Uuid,
}

/// A response containing the known replicas for a given wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetReplicasResponse {
    /// The number of replicas for the wallet
    pub replicas: Vec<WrappedPeerId>,
}
