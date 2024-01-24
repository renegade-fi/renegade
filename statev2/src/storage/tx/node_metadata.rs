//! Storage access methods for the local node's metadata

use common::types::gossip::{ClusterId, WrappedPeerId};
use flexbuffers::{DeserializationError, SerializationError};
use libmdbx::{TransactionKind, RW};
use libp2p::identity::Keypair;

use crate::{storage::error::StorageError, NODE_METADATA_TABLE};

use super::StateTxn;

// -------------
// | Constants |
// -------------

/// The name of the peer ID key in the node metadata table
const PEER_ID_KEY: &str = "peer-id";
/// The name of the cluster ID key in the node metadata table
const CLUSTER_ID_KEY: &str = "cluster-id";
/// The name of the libp2p keypair key in the node metadata table
const NODE_KEYPAIR_KEY: &str = "node-keypair";

// -----------
// | Helpers |
// -----------

/// Helper function to create a `StorageError::NotFound` error
///
/// Values in the node metadata should always be present, so we promote
/// `Option::None` to an error
fn err_not_found(key: &str) -> StorageError {
    StorageError::NotFound(format!("node metadata key {} not found", key))
}

// -----------
// | Getters |
// -----------

/// We expect the node metadata table to always contain its relevant values (it
/// should be initialized at startup) so we promote `Option::None` to an error
impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the local node's peer ID
    pub fn get_peer_id(&self) -> Result<WrappedPeerId, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &PEER_ID_KEY.to_string())?
            .ok_or_else(|| err_not_found(PEER_ID_KEY))
    }

    /// Get the local node's cluster ID
    pub fn get_cluster_id(&self) -> Result<ClusterId, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &CLUSTER_ID_KEY.to_string())?
            .ok_or_else(|| err_not_found(CLUSTER_ID_KEY))
    }

    /// Get the local node's libp2p keypair
    pub fn get_node_keypair(&self) -> Result<Keypair, StorageError> {
        let key_bytes: Vec<u8> = self
            .inner()
            .read(NODE_METADATA_TABLE, &NODE_KEYPAIR_KEY.to_string())?
            .ok_or_else(|| err_not_found(NODE_KEYPAIR_KEY))?;

        Keypair::from_protobuf_encoding(&key_bytes)
            .map_err(|e| StorageError::Deserialization(DeserializationError::Serde(e.to_string())))
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Set the local node's peer ID
    pub fn set_peer_id(&self, peer_id: &WrappedPeerId) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &PEER_ID_KEY.to_string(), peer_id)
    }

    /// Set the local node's cluster ID
    pub fn set_cluster_id(&self, cluster_id: &ClusterId) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &CLUSTER_ID_KEY.to_string(), cluster_id)
    }

    /// Set the local node's libp2p keypair
    pub fn set_node_keypair(&self, keypair: &Keypair) -> Result<(), StorageError> {
        let key_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| StorageError::Serialization(SerializationError::Serde(e.to_string())))?;
        self.inner().write(NODE_METADATA_TABLE, &NODE_KEYPAIR_KEY.to_string(), &key_bytes)
    }
}
