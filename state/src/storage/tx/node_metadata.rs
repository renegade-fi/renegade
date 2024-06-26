//! Storage access methods for the local node's metadata

use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint};
use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    wallet::WalletIdentifier,
};
use libmdbx::{TransactionKind, RW};
use libp2p::core::Multiaddr;
use libp2p::identity::Keypair;
use util::err_str;

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
/// The name of the local peer addr in the node metadata table
const LOCAL_ADDR_KEY: &str = "local-addr";
/// The key for the local relayer's wallet ID in the node metadata table
const LOCAL_WALLET_ID_KEY: &str = "local-wallet-id";
/// The key for the local relayer's fee decryption key in the node metadata
/// table
const LOCAL_RELAYER_DECRYPTION_KEY: &str = "local-relayer-decryption-key";
/// The key for the local relayer's match take rate in the node metadata table
const RELAYER_TAKE_RATE_KEY: &str = "relayer-take-rate";
/// The key for the local relayer's auto-redeem fees flag in the node metadata
const AUTO_REDEEM_FEES_KEY: &str = "auto-redeem-fees";

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

        Keypair::from_protobuf_encoding(&key_bytes).map_err(err_str!(StorageError::Other))
    }

    /// Get the local node's addr
    pub fn get_local_addr(&self) -> Result<Multiaddr, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &LOCAL_ADDR_KEY.to_string())?
            .ok_or_else(|| err_not_found(LOCAL_ADDR_KEY))
    }

    /// Get the wallet ID of the local relayer's wallet
    pub fn get_local_node_wallet(&self) -> Result<WalletIdentifier, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &LOCAL_WALLET_ID_KEY.to_string())?
            .ok_or_else(|| err_not_found(LOCAL_WALLET_ID_KEY))
    }

    /// Get the local relayer's fee decryption key
    pub fn get_fee_decryption_key(&self) -> Result<DecryptionKey, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &LOCAL_RELAYER_DECRYPTION_KEY.to_string())?
            .ok_or_else(|| err_not_found(LOCAL_RELAYER_DECRYPTION_KEY))
    }

    /// Get the local relayer's match take rate
    pub fn get_relayer_take_rate(&self) -> Result<FixedPoint, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &RELAYER_TAKE_RATE_KEY.to_string())?
            .ok_or_else(|| err_not_found(RELAYER_TAKE_RATE_KEY))
    }

    /// Get the local relayer's auto-redeem fees flag
    pub fn get_auto_redeem_fees(&self) -> Result<bool, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &AUTO_REDEEM_FEES_KEY.to_string())?
            .ok_or_else(|| err_not_found(AUTO_REDEEM_FEES_KEY))
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
        let key_bytes = keypair.to_protobuf_encoding().map_err(err_str!(StorageError::Other))?;
        self.inner().write(NODE_METADATA_TABLE, &NODE_KEYPAIR_KEY.to_string(), &key_bytes)
    }

    /// Set the local addr of the node
    pub fn set_local_addr(&self, addr: &Multiaddr) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_ADDR_KEY.to_string(), addr)
    }

    /// Set the wallet ID of the local relayer's wallet
    pub fn set_local_node_wallet(&self, wallet_id: WalletIdentifier) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_WALLET_ID_KEY.to_string(), &wallet_id)
    }

    /// Set the local relayer's fee decryption key
    pub fn set_fee_decryption_key(&self, fee_key: &DecryptionKey) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_RELAYER_DECRYPTION_KEY.to_string(), fee_key)
    }

    /// Set the local relayer's match take rate
    pub fn set_relayer_take_rate(&self, take_rate: &FixedPoint) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &RELAYER_TAKE_RATE_KEY.to_string(), take_rate)
    }

    /// Set the local relayer's auto-redeem fees flag
    pub fn set_auto_redeem_fees(&self, auto_redeem_fees: bool) -> Result<(), StorageError> {
        self.inner().write(
            NODE_METADATA_TABLE,
            &AUTO_REDEEM_FEES_KEY.to_string(),
            &auto_redeem_fees,
        )
    }
}
