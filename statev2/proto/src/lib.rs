use mpc_stark::algebra::scalar::Scalar;
use uuid::{Error as UuidError, Uuid};

pub use protos::*;

#[deny(missing_docs)]
#[deny(clippy::missing_docs_in_private_items)]
#[deny(unsafe_code)]

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

/// Scalar
impl From<ProtoScalar> for Scalar {
    fn from(scalar: ProtoScalar) -> Self {
        Scalar::from_be_bytes_mod_order(&scalar.value)
    }
}

#[cfg(test)]
mod tests {
    use super::{AddOrder, AddPeers, NetworkOrder, PeerInfo};
    use prost::Message;

    /// Tests the add new peer message
    #[test]
    fn test_new_peer_serialization() {
        let msg = AddPeers {
            peers: vec![PeerInfo {
                peer_id: Some("1234".to_string().into()),
                addr: "127.0.0.1:5000".to_string(),
                cluster_id: Some("1234".to_string().into()),
                cluster_auth_sig: vec![],
            }],
        };

        let bytes = msg.encode_to_vec();
        let recovered: AddPeers = AddPeers::decode(bytes.as_slice()).unwrap();

        assert_eq!(msg, recovered);
    }

    /// Tests the add new order message
    #[test]
    fn test_new_order_serialization() {
        let msg = AddOrder {
            order: Some(NetworkOrder {
                id: Some("1234".to_string().into()),
                ..Default::default()
            }),
        };

        let bytes = msg.encode_to_vec();
        let recovered: AddOrder = AddOrder::decode(bytes.as_slice()).unwrap();

        assert_eq!(msg, recovered);
    }
}
