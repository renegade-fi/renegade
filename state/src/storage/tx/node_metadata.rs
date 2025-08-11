//! Storage access methods for the local node's metadata
use circuit_types::{Address, fixed_point::FixedPoint};
use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    wallet::WalletIdentifier,
};
use config::RelayerFeeKey;
use libmdbx::{RW, TransactionKind};
use libp2p::core::Multiaddr;
use libp2p::identity::Keypair;
use util::err_str;

use crate::{NODE_METADATA_TABLE, storage::error::StorageError};

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
const LOCAL_RELAYER_FEE_KEY: &str = "local-relayer-fee-key";
/// The key for the local relayer's maximum match fee in the node metadata table
const MAX_RELAYER_FEE_KEY: &str = "max-relayer-fee";
/// The key for the local relayer's default match fee in the node metadata table
const DEFAULT_RELAYER_FEE_KEY: &str = "default-relayer-fee";
/// The key for the local relayer's external fee address in the node metadata
/// table
const EXTERNAL_FEE_ADDR_KEY: &str = "external-fee-addr";
/// The key for the local relayer's auto-redeem fees flag in the node metadata
const AUTO_REDEEM_FEES_KEY: &str = "auto-redeem-fees";
/// The key for the local relayer's historical state enabled flag in the node
/// metadata table
const HISTORICAL_STATE_ENABLED_KEY: &str = "historical-state-enabled";

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
    pub fn get_local_node_wallet(&self) -> Result<Option<WalletIdentifier>, StorageError> {
        self.inner().read(NODE_METADATA_TABLE, &LOCAL_WALLET_ID_KEY.to_string())
    }

    /// Get the local relayer's fee decryption key
    pub fn get_fee_key(&self) -> Result<RelayerFeeKey, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &LOCAL_RELAYER_FEE_KEY.to_string())?
            .ok_or_else(|| err_not_found(LOCAL_RELAYER_FEE_KEY))
    }

    /// Get the local relayer's maximum match fee
    pub fn get_max_relayer_fee(&self) -> Result<FixedPoint, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &MAX_RELAYER_FEE_KEY.to_string())?
            .ok_or_else(|| err_not_found(MAX_RELAYER_FEE_KEY))
    }

    /// Get the local relayer's default match fee
    pub fn get_default_relayer_fee(&self) -> Result<FixedPoint, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &DEFAULT_RELAYER_FEE_KEY.to_string())?
            .ok_or_else(|| err_not_found(DEFAULT_RELAYER_FEE_KEY))
    }

    /// Get the local relayer's external fee address
    pub fn get_external_fee_addr(&self) -> Result<Option<Address>, StorageError> {
        self.inner().read(NODE_METADATA_TABLE, &EXTERNAL_FEE_ADDR_KEY.to_string())
    }

    /// Get the local relayer's auto-redeem fees flag
    pub fn get_auto_redeem_fees(&self) -> Result<bool, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &AUTO_REDEEM_FEES_KEY.to_string())?
            .ok_or_else(|| err_not_found(AUTO_REDEEM_FEES_KEY))
    }

    /// Get the local relayer's historical state enabled flag
    pub fn get_historical_state_enabled(&self) -> Result<bool, StorageError> {
        self.inner()
            .read(NODE_METADATA_TABLE, &HISTORICAL_STATE_ENABLED_KEY.to_string())?
            .ok_or_else(|| err_not_found(HISTORICAL_STATE_ENABLED_KEY))
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
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_ADDR_KEY.to_string(), addr)
    }

    /// Set the wallet ID of the local relayer's wallet
    pub fn set_local_node_wallet(&self, wallet_id: WalletIdentifier) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_WALLET_ID_KEY.to_string(), &wallet_id)
    }

    /// Set the local relayer's fee decryption key
    pub fn set_fee_key(&self, fee_key: &RelayerFeeKey) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &LOCAL_RELAYER_FEE_KEY.to_string(), fee_key)
    }

    /// Set the local relayer's maximum match fee
    pub fn set_max_relayer_fee(&self, max_relayer_fee: &FixedPoint) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &MAX_RELAYER_FEE_KEY.to_string(), max_relayer_fee)
    }

    /// Set the default relayer match fee
    pub fn set_default_relayer_fee(
        &self,
        default_relayer_fee: &FixedPoint,
    ) -> Result<(), StorageError> {
        self.inner().write(
            NODE_METADATA_TABLE,
            &DEFAULT_RELAYER_FEE_KEY.to_string(),
            default_relayer_fee,
        )
    }

    /// Set the local relayer's external fee address
    pub fn set_external_fee_addr(&self, addr: &Address) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &EXTERNAL_FEE_ADDR_KEY.to_string(), addr)
    }

    /// Set the local relayer's auto-redeem fees flag
    pub fn set_auto_redeem_fees(&self, auto_redeem_fees: bool) -> Result<(), StorageError> {
        self.inner().write(
            NODE_METADATA_TABLE,
            &AUTO_REDEEM_FEES_KEY.to_string(),
            &auto_redeem_fees,
        )
    }

    /// Set the local relayer's historical state enabled flag
    pub fn set_historical_state_enabled(&self, enabled: bool) -> Result<(), StorageError> {
        self.inner().write(NODE_METADATA_TABLE, &HISTORICAL_STATE_ENABLED_KEY.to_string(), &enabled)
    }
}
