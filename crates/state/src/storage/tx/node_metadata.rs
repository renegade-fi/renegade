//! Storage access methods for the local node's metadata
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use circuit_types::{
    baby_jubjub::BabyJubJubPoint, elgamal::EncryptionKey, fixed_point::FixedPoint,
};
use darkpool_types::rkyv_remotes::{AddressDef, BabyJubJubPointDef, FixedPointDef};
use libmdbx::{RW, TransactionKind};
use libp2p::core::Multiaddr;
use libp2p::identity::Keypair;
use std::str::FromStr;
use types_core::AccountId;
use types_gossip::{ClusterId, MultiaddrDef, WrappedPeerId};
use util::err_str;

use crate::{
    NODE_METADATA_TABLE,
    storage::{error::StorageError, traits::RkyvWith},
};

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
/// The name of the local peer addr in the node metadata table
const LOCAL_ADDR_KEY: &str = "local-addr";
/// The key for the local relayer's account ID in the node metadata table
const LOCAL_ACCOUNT_ID_KEY: &str = "local-account-id";
/// The key for the local relayer's fee encryption key in the node metadata
/// table
const LOCAL_RELAYER_FEE_KEY: &str = "local-relayer-fee-key";
/// The key for the local relayer's maximum match fee in the node metadata table
const MAX_RELAYER_FEE_KEY: &str = "max-relayer-fee";
/// The key for the local relayer's default match fee in the node metadata table
const DEFAULT_RELAYER_FEE_KEY: &str = "default-relayer-fee";
/// The key for the local relayer's fee address in the node metadata table
const RELAYER_FEE_ADDR_KEY: &str = "relayer-fee-addr";
/// The key for the local relayer's historical state enabled flag in the node
/// metadata table
const HISTORICAL_STATE_ENABLED_KEY: &str = "historical-state-enabled";
/// The key for the executor private key in the node metadata table
const EXECUTOR_KEY: &str = "executor-key";

/// A type alias for a with-wrapped baby jubjub point
type WithBabyJubJubPoint = RkyvWith<BabyJubJubPoint, BabyJubJubPointDef>;
/// A type alias for a with-wrapped fixed point
type WithFixedPoint = RkyvWith<FixedPoint, FixedPointDef>;
/// A type alias for a with-wrapped address
type WithAddress = RkyvWith<Address, AddressDef>;
/// A type alias for a with-wrapped multiaddr
type WithMultiaddr = RkyvWith<Multiaddr, MultiaddrDef>;

// -----------
// | Helpers |
// -----------

/// Helper function to create a `StorageError::NotFound` error
///
/// Values in the node metadata should always be present, so we promote
/// `Option::None` to an error
fn err_not_found(key: &str) -> StorageError {
    StorageError::NotFound(format!("node metadata key {key} not found"))
}

// -----------
// | Getters |
// -----------

/// We expect the node metadata table to always contain its relevant values (it
/// should be initialized at startup) so we promote `Option::None` to an error
impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the local node's peer ID
    pub fn get_peer_id(&self) -> Result<WrappedPeerId, StorageError> {
        self.inner()
            .read::<_, WrappedPeerId>(NODE_METADATA_TABLE, &PEER_ID_KEY.to_string())?
            .ok_or_else(|| err_not_found(PEER_ID_KEY))?
            .deserialize()
    }

    /// Get the local node's cluster ID
    pub fn get_cluster_id(&self) -> Result<ClusterId, StorageError> {
        self.inner()
            .read::<_, ClusterId>(NODE_METADATA_TABLE, &CLUSTER_ID_KEY.to_string())?
            .ok_or_else(|| err_not_found(CLUSTER_ID_KEY))?
            .deserialize()
    }

    /// Get the local node's libp2p keypair
    pub fn get_node_keypair(&self) -> Result<Keypair, StorageError> {
        let key_bytes: Vec<u8> = self
            .inner()
            .read::<_, Vec<u8>>(NODE_METADATA_TABLE, &NODE_KEYPAIR_KEY.to_string())?
            .ok_or_else(|| err_not_found(NODE_KEYPAIR_KEY))?
            .deserialize()?;

        Keypair::from_protobuf_encoding(&key_bytes).map_err(err_str!(StorageError::Other))
    }

    /// Get the local node's addr
    pub fn get_local_addr(&self) -> Result<Multiaddr, StorageError> {
        self.inner()
            .read::<_, WithMultiaddr>(NODE_METADATA_TABLE, &LOCAL_ADDR_KEY.to_string())?
            .ok_or_else(|| err_not_found(LOCAL_ADDR_KEY))?
            .deserialize_with()
    }

    /// Get the account ID of the local relayer's account
    pub fn get_local_node_wallet(&self) -> Result<Option<AccountId>, StorageError> {
        self.inner()
            .read::<_, AccountId>(NODE_METADATA_TABLE, &LOCAL_ACCOUNT_ID_KEY.to_string())?
            .map(|a| a.deserialize())
            .transpose()
    }

    /// Get the local relayer's fee encryption key
    pub fn get_fee_key(&self) -> Result<EncryptionKey, StorageError> {
        self.inner()
            .read::<_, WithBabyJubJubPoint>(
                NODE_METADATA_TABLE,
                &LOCAL_RELAYER_FEE_KEY.to_string(),
            )?
            .ok_or_else(|| err_not_found(LOCAL_RELAYER_FEE_KEY))?
            .deserialize_with()
    }

    /// Get the local relayer's maximum match fee
    pub fn get_max_relayer_fee(&self) -> Result<FixedPoint, StorageError> {
        self.inner()
            .read::<_, WithFixedPoint>(NODE_METADATA_TABLE, &MAX_RELAYER_FEE_KEY.to_string())?
            .ok_or_else(|| err_not_found(MAX_RELAYER_FEE_KEY))?
            .deserialize_with()
    }

    /// Get the local relayer's default match fee
    pub fn get_default_relayer_fee(&self) -> Result<FixedPoint, StorageError> {
        self.inner()
            .read::<_, WithFixedPoint>(NODE_METADATA_TABLE, &DEFAULT_RELAYER_FEE_KEY.to_string())?
            .ok_or_else(|| err_not_found(DEFAULT_RELAYER_FEE_KEY))?
            .deserialize_with()
    }

    /// Get the local relayer's fee address
    pub fn get_relayer_fee_addr(&self) -> Result<Option<Address>, StorageError> {
        self.inner()
            .read::<_, WithAddress>(NODE_METADATA_TABLE, &RELAYER_FEE_ADDR_KEY.to_string())?
            .map(|a| a.deserialize_with())
            .transpose()
    }

    /// Get the local relayer's historical state enabled flag
    pub fn get_historical_state_enabled(&self) -> Result<bool, StorageError> {
        self.inner()
            .read::<_, bool>(NODE_METADATA_TABLE, &HISTORICAL_STATE_ENABLED_KEY.to_string())?
            .ok_or_else(|| err_not_found(HISTORICAL_STATE_ENABLED_KEY))?
            .deserialize()
    }

    /// Get the executor private key
    pub fn get_executor_key(&self) -> Result<PrivateKeySigner, StorageError> {
        let hex_str: String = self
            .inner()
            .read::<_, String>(NODE_METADATA_TABLE, &EXECUTOR_KEY.to_string())?
            .ok_or_else(|| err_not_found(EXECUTOR_KEY))?
            .deserialize()?;
        PrivateKeySigner::from_str(&hex_str).map_err(err_str!(StorageError::Other))
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
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
        let key_bytes = keypair.to_protobuf_encoding().map_err(err_str!(StorageError::Other))?;
        self.inner().write(NODE_METADATA_TABLE, &NODE_KEYPAIR_KEY.to_string(), &key_bytes)
    }

    /// Set the local addr of the node
    pub fn set_local_addr(&self, addr: &Multiaddr) -> Result<(), StorageError> {
        let wrapped = WithMultiaddr::cast(addr);
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_ADDR_KEY.to_string(), wrapped)
    }

    /// Set the account ID of the local relayer's account
    pub fn set_local_node_wallet(&self, account_id: AccountId) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_ACCOUNT_ID_KEY.to_string(), &account_id)
    }

    /// Set the local relayer's fee encryption key
    pub fn set_fee_key(&self, fee_key: &EncryptionKey) -> Result<(), StorageError> {
        let wrapped = WithBabyJubJubPoint::cast(fee_key);
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_RELAYER_FEE_KEY.to_string(), wrapped)
    }

    /// Set the local relayer's maximum match fee
    pub fn set_max_relayer_fee(&self, max_relayer_fee: &FixedPoint) -> Result<(), StorageError> {
        let wrapped = WithFixedPoint::cast(max_relayer_fee);
        self.inner().write(NODE_METADATA_TABLE, &MAX_RELAYER_FEE_KEY.to_string(), wrapped)
    }

    /// Set the default relayer match fee
    pub fn set_default_relayer_fee(
        &self,
        default_relayer_fee: &FixedPoint,
    ) -> Result<(), StorageError> {
        let wrapped = WithFixedPoint::cast(default_relayer_fee);
        self.inner().write(NODE_METADATA_TABLE, &DEFAULT_RELAYER_FEE_KEY.to_string(), wrapped)
    }

    /// Set the local relayer's fee address
    pub fn set_relayer_fee_addr(&self, addr: &Address) -> Result<(), StorageError> {
        let wrapped = WithAddress::cast(addr);
        self.inner().write(NODE_METADATA_TABLE, &RELAYER_FEE_ADDR_KEY.to_string(), wrapped)
    }

    /// Set the local relayer's historical state enabled flag
    pub fn set_historical_state_enabled(&self, enabled: bool) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &HISTORICAL_STATE_ENABLED_KEY.to_string(), &enabled)
    }

    /// Set the executor private key (stored as hex string)
    pub fn set_executor_key(&self, executor_key: &PrivateKeySigner) -> Result<(), StorageError> {
        // Convert PrivateKeySigner to hex string by accessing the secret key bytes
        let secret_key_bytes = executor_key.to_bytes();
        let hex_str = util::hex::bytes_to_hex_string(secret_key_bytes.as_slice());
        self.inner().write(NODE_METADATA_TABLE, &EXECUTOR_KEY.to_string(), &hex_str)
    }
}
