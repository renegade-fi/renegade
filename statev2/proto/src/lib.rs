//! Defines proto types for state transitions and type operations on them

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{collections::HashSet, str::FromStr, sync::atomic::AtomicU64};

use circuit_types::{
    balance::Balance as CircuitBalance,
    fee::Fee as CircuitFee,
    fixed_point::FixedPoint,
    keychain::{
        PublicIdentificationKey, PublicKeyChain as CircuitPublicKeyChain, SecretIdentificationKey,
    },
    order::{Order as CircuitOrder, OrderSide as CircuitOrderSide},
    traits::BaseType,
    SizedWalletShare,
};
use common::types::{
    gossip::{ClusterId as RuntimeClusterId, PeerInfo as RuntimePeerInfo, WrappedPeerId},
    merkle::MerkleAuthenticationPath,
    network_order::{
        NetworkOrder as RuntimeNetworkOrder, NetworkOrderState as RuntimeNetworkOrderState,
    },
    proof_bundles::OrderValidityProofBundle,
    wallet::{
        KeyChain as RuntimeKeyChain, OrderIdentifier, PrivateKeyChain as RuntimePrivateKeyChain,
        Wallet as RuntimeWallet, WalletMetadata as RuntimeWalletMetadata,
    },
};
use error::StateProtoError;
use indexmap::IndexMap;
use itertools::Itertools;
use mpc_stark::algebra::scalar::Scalar;
use multiaddr::Multiaddr;
use num_bigint::BigUint;
use uuid::Uuid;

pub use protos::*;
pub mod error;

/// An error emitted when the siblings array in a Merkle path is incorrectly sized
const ERR_INCORRECT_SIBLINGS_SIZE: &str = "incorrect number of siblings";

/// Protobuf definitions for state transitions
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
mod protos {
    include!(concat!(env!("OUT_DIR"), "/state.rs"));
}

// ----------------------------------
// | Type Definitions + Conversions |
// ----------------------------------

/// PeerId
impl From<String> for PeerId {
    fn from(id: String) -> Self {
        Self { id }
    }
}

/// ClusterId
impl From<String> for ClusterId {
    fn from(id: String) -> Self {
        Self { id }
    }
}

/// UUID
impl From<String> for ProtoUuid {
    fn from(value: String) -> Self {
        Self { value }
    }
}

impl TryFrom<ProtoUuid> for Uuid {
    type Error = StateProtoError;
    fn try_from(uuid: ProtoUuid) -> Result<Self, Self::Error> {
        Uuid::parse_str(&uuid.value).map_err(|e| StateProtoError::ParseError(e.to_string()))
    }
}

impl From<Uuid> for ProtoUuid {
    fn from(value: Uuid) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

/// Scalar
impl From<ProtoScalar> for Scalar {
    fn from(scalar: ProtoScalar) -> Self {
        Scalar::from_be_bytes_mod_order(&scalar.value)
    }
}

impl From<Scalar> for ProtoScalar {
    fn from(value: Scalar) -> Self {
        Self {
            value: value.to_bytes_be(),
        }
    }
}

/// BigInt
impl From<ProtoBigInt> for BigUint {
    fn from(big_int: ProtoBigInt) -> Self {
        BigUint::from_bytes_le(&big_int.value)
    }
}

impl From<BigUint> for ProtoBigInt {
    fn from(value: BigUint) -> Self {
        Self {
            value: value.to_bytes_le(),
        }
    }
}

/// ClusterId
impl From<ClusterId> for RuntimeClusterId {
    fn from(value: ClusterId) -> Self {
        RuntimeClusterId::from_str(&value.id).expect("infallible")
    }
}

/// PeerInfo
impl TryFrom<PeerId> for WrappedPeerId {
    type Error = StateProtoError;
    fn try_from(value: PeerId) -> Result<Self, Self::Error> {
        WrappedPeerId::from_str(&value.id)
            .map_err(|e| StateProtoError::ParseError(format!("PeerId: {}", e)))
    }
}

impl TryFrom<PeerInfo> for RuntimePeerInfo {
    type Error = StateProtoError;
    fn try_from(info: PeerInfo) -> Result<Self, Self::Error> {
        // Parse the individual fields from the proto
        let peer_id = info.peer_id.ok_or_else(|| StateProtoError::MissingField {
            field_name: "peer_id".to_string(),
        })?;

        let addr = Multiaddr::from_str(&info.addr)
            .map_err(|e| StateProtoError::ParseError(format!("Multiaddr: {e}")))?;

        let cluster_id = info
            .cluster_id
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "cluster_id".to_string(),
            })?;

        // Collect into the runtime type
        Ok(RuntimePeerInfo {
            peer_id: WrappedPeerId::try_from(peer_id)?,
            addr,
            last_heartbeat: AtomicU64::new(0),
            cluster_id: RuntimeClusterId::from(cluster_id),
            cluster_auth_signature: info.cluster_auth_sig,
        })
    }
}

// NetworkOrder
impl From<NetworkOrderState> for RuntimeNetworkOrderState {
    fn from(value: NetworkOrderState) -> Self {
        match value {
            NetworkOrderState::Received => RuntimeNetworkOrderState::Received,
            NetworkOrderState::Verified => RuntimeNetworkOrderState::Verified,
            NetworkOrderState::Cancelled => RuntimeNetworkOrderState::Cancelled,
        }
    }
}

impl TryFrom<NetworkOrder> for RuntimeNetworkOrder {
    type Error = StateProtoError;
    fn try_from(order: NetworkOrder) -> Result<Self, Self::Error> {
        // Parse the individual fields
        let id: Uuid = order
            .id
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "id".to_string(),
            })
            .and_then(|id| {
                Uuid::try_from(id).map_err(|e| StateProtoError::ParseError(e.to_string()))
            })?;

        let nullifier: Scalar = order
            .nullifier
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "nullifier".to_string(),
            })?
            .into();

        let cluster_id = order
            .cluster
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "cluster_id".to_string(),
            })?;

        let state = order.state();

        let proof = order.proof;
        let validity_proofs: Option<OrderValidityProofBundle> = if proof.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&proof).map_err(|e| {
                StateProtoError::ParseError(format!("OrderValidityProofBundle: {}", e))
            })?)
        };

        Ok(Self {
            id,
            public_share_nullifier: nullifier,
            cluster: RuntimeClusterId::from(cluster_id),
            state: state.into(),
            local: false,
            validity_proofs,
            validity_proof_witnesses: None,
        })
    }
}

/// Wallet
impl From<Balance> for CircuitBalance {
    fn from(value: Balance) -> Self {
        let mint: BigUint = value.mint.unwrap_or_default().into();
        let amount: u64 = value.amount;

        CircuitBalance { mint, amount }
    }
}

impl From<OrderSide> for CircuitOrderSide {
    fn from(value: OrderSide) -> Self {
        match value {
            OrderSide::Buy => CircuitOrderSide::Buy,
            OrderSide::Sell => CircuitOrderSide::Sell,
        }
    }
}

impl From<Order> for CircuitOrder {
    fn from(value: Order) -> Self {
        let quote_mint: BigUint = value.quote_mint.clone().unwrap_or_default().into();
        let base_mint: BigUint = value.base_mint.clone().unwrap_or_default().into();
        let side: CircuitOrderSide = value.side().into();
        let amount = value.amount;
        let worst_case_price = FixedPoint::from_f64_round_down(value.worst_case_price);
        let timestamp = value.timestamp;

        CircuitOrder {
            quote_mint,
            base_mint,
            side,
            amount,
            worst_case_price,
            timestamp,
        }
    }
}

impl From<Fee> for CircuitFee {
    fn from(value: Fee) -> Self {
        let settle_key: BigUint = value.settle_key.clone().unwrap_or_default().into();
        let gas_addr: BigUint = value.gas_addr.clone().unwrap_or_default().into();
        let gas_token_amount = value.gas_amount;
        let percentage_fee = FixedPoint::from_f64_round_down(value.percentage_fee);

        CircuitFee {
            settle_key,
            gas_addr,
            gas_token_amount,
            percentage_fee,
        }
    }
}

impl TryFrom<PrivateKeyChain> for RuntimePrivateKeyChain {
    type Error = StateProtoError;

    fn try_from(value: PrivateKeyChain) -> Result<Self, Self::Error> {
        let sk_root = if value.sk_root.is_empty() {
            None
        } else {
            Some(
                serde_json::from_slice(&value.sk_root)
                    .map_err(|e| StateProtoError::ParseError(e.to_string()))?,
            )
        };

        let sk_match: Scalar = value
            .sk_match
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "sk_match".to_string(),
            })?
            .into();

        Ok(RuntimePrivateKeyChain {
            sk_root,
            sk_match: SecretIdentificationKey { key: sk_match },
        })
    }
}

impl TryFrom<PublicKeyChain> for CircuitPublicKeyChain {
    type Error = StateProtoError;

    fn try_from(value: PublicKeyChain) -> Result<Self, Self::Error> {
        let pk_root = serde_json::from_slice(&value.pk_root)
            .map_err(|e| StateProtoError::ParseError(e.to_string()))?;
        let pk_match: Scalar = value
            .pk_match
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "pk_match".to_string(),
            })?
            .into();

        Ok(CircuitPublicKeyChain {
            pk_root,
            pk_match: PublicIdentificationKey { key: pk_match },
        })
    }
}

impl TryFrom<KeyChain> for RuntimeKeyChain {
    type Error = StateProtoError;

    fn try_from(value: KeyChain) -> Result<Self, Self::Error> {
        let public_keys: CircuitPublicKeyChain = value
            .public_keys
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "public_key_chain".to_string(),
            })
            .and_then(TryInto::try_into)?;
        let secret_keys: RuntimePrivateKeyChain = value
            .secret_keys
            .clone()
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "private_key_chain".to_string(),
            })
            .and_then(TryInto::try_into)?;

        Ok(RuntimeKeyChain {
            public_keys,
            secret_keys,
        })
    }
}

impl TryFrom<WalletMetadata> for RuntimeWalletMetadata {
    type Error = StateProtoError;

    fn try_from(value: WalletMetadata) -> Result<Self, Self::Error> {
        let replicas = value
            .replicas
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(RuntimeWalletMetadata { replicas })
    }
}

impl TryFrom<WalletAuthenticationPath> for MerkleAuthenticationPath {
    type Error = StateProtoError;

    fn try_from(path: WalletAuthenticationPath) -> Result<Self, Self::Error> {
        let path_siblings = path
            .path_siblings
            .into_iter()
            .map(Into::<Scalar>::into)
            .collect_vec()
            .try_into()
            .map_err(|_| StateProtoError::ParseError(ERR_INCORRECT_SIBLINGS_SIZE.to_string()))?;

        let leaf_index = BigUint::from(path.leaf_index);
        let value = path
            .value
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "value".to_string(),
            })?
            .into();

        Ok(MerkleAuthenticationPath {
            path_siblings,
            leaf_index,
            value,
        })
    }
}

impl TryFrom<Wallet> for RuntimeWallet {
    type Error = StateProtoError;
    fn try_from(value: Wallet) -> Result<Self, Self::Error> {
        let id = Uuid::try_from(value.id.unwrap_or_default())?;
        let balances: Vec<CircuitBalance> = value.balances.into_iter().map(Into::into).collect();

        let orders: IndexMap<OrderIdentifier, CircuitOrder> = value
            .orders
            .into_iter()
            .map(|o| {
                let id =
                    o.id.clone()
                        .ok_or_else(|| StateProtoError::MissingField {
                            field_name: "order id".to_string(),
                        })
                        .and_then(TryInto::try_into)?;

                Ok((id, o.into()))
            })
            .collect::<Result<_, _>>()?;

        let fees: Vec<CircuitFee> = value.fees.into_iter().map(Into::into).collect();

        let key_chain: RuntimeKeyChain = value
            .keychain
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "keychain".to_string(),
            })
            .and_then(TryInto::try_into)?;

        let blinder: Scalar = value
            .blinder
            .ok_or_else(|| StateProtoError::MissingField {
                field_name: "blinder".to_string(),
            })?
            .into();

        // Zero pad the shares to avoid panicking in the `from_scalars` method
        // in case the message is malformed. The correctness of the secret shares is assumed
        // to be validated elsewhere
        let private_shares = SizedWalletShare::from_scalars(
            &mut value
                .private_shares
                .into_iter()
                .map(|s| s.into())
                .chain(std::iter::repeat(Scalar::zero())),
        );
        let blinded_public_shares = SizedWalletShare::from_scalars(
            &mut value
                .blinded_public_shares
                .into_iter()
                .map(|s| s.into())
                .chain(std::iter::repeat(Scalar::zero())),
        );

        let merkle_proof: Option<MerkleAuthenticationPath> =
            value.opening.map(TryInto::try_into).transpose()?;

        Ok(RuntimeWallet {
            wallet_id: id,
            orders,
            balances: balances.into_iter().map(|b| (b.mint.clone(), b)).collect(),
            fees,
            key_chain,
            blinder,
            metadata: RuntimeWalletMetadata::default(),
            private_shares,
            blinded_public_shares,
            merkle_proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{AddOrderBuilder, AddPeersBuilder, NetworkOrderBuilder, PeerInfoBuilder};

    use super::{AddOrder, AddPeers};
    use prost::Message;

    /// Tests the add new peer message
    #[test]
    fn test_new_peer_serialization() {
        let new_peer = PeerInfoBuilder::default()
            .peer_id("1234".to_string().into())
            .build()
            .unwrap();
        let msg = AddPeersBuilder::default()
            .peers(vec![new_peer])
            .build()
            .unwrap();

        let bytes = msg.encode_to_vec();
        let recovered: AddPeers = AddPeers::decode(bytes.as_slice()).unwrap();

        assert_eq!(msg, recovered);
    }

    /// Tests the add new order message
    #[test]
    fn test_new_order_serialization() {
        let order = NetworkOrderBuilder::default()
            .id("1234".to_string().into())
            .build()
            .unwrap();
        let msg = AddOrderBuilder::default().order(order).build().unwrap();

        let bytes = msg.encode_to_vec();
        let recovered: AddOrder = AddOrder::decode(bytes.as_slice()).unwrap();

        assert_eq!(msg, recovered);
    }
}
