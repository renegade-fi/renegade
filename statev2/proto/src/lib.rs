//! Defines proto types for state transitions and type operations on them

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{str::FromStr, sync::atomic::AtomicU64};

use common::types::{
    gossip::{ClusterId as RuntimeClusterId, PeerInfo as RuntimePeerInfo, WrappedPeerId},
    network_order::{
        NetworkOrder as RuntimeNetworkOrder, NetworkOrderState as RuntimeNetworkOrderState,
    },
    proof_bundles::OrderValidityProofBundle,
};
use error::StateProtoError;
use mpc_stark::algebra::scalar::Scalar;
use multiaddr::Multiaddr;
use uuid::{Error as UuidError, Uuid};

pub use protos::*;
pub mod error;

/// Protobuf definitions for state transitions
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
mod protos {
    include!(concat!(env!("OUT_DIR"), "/state.rs"));
}

// --------------------
// | Type Definitions |
// --------------------

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
    type Error = UuidError;
    fn try_from(uuid: ProtoUuid) -> Result<Self, Self::Error> {
        Uuid::parse_str(&uuid.value)
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
