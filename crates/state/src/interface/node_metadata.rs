//! Stores state information relating to the node's configuration

use circuit_types::{Address, fixed_point::FixedPoint};
use common::types::{
    gossip::{ClusterId, PeerInfo, WrappedPeerId},
    wallet::{Wallet, WalletIdentifier, derivation::derive_wallet_id},
};
use config::{RelayerConfig, RelayerFeeKey};
use libp2p::{core::Multiaddr, identity::Keypair};
use tracing::warn;
use util::res_some;

use crate::{NODE_METADATA_TABLE, StateInner, error::StateError};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer ID of the local node
    pub fn get_peer_id(&self) -> Result<WrappedPeerId, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_peer_id().map_err(StateError::Db))
    }

    /// Get the cluster ID of the local node
    pub fn get_cluster_id(&self) -> Result<ClusterId, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_cluster_id().map_err(StateError::Db))
    }

    /// Get the libp2p keypair of the local node
    pub fn get_node_keypair(&self) -> Result<Keypair, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_node_keypair().map_err(StateError::Db))
    }

    /// Get the wallet ID that the local relayer owns
    pub fn get_relayer_wallet_id(&self) -> Result<Option<WalletIdentifier>, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_local_node_wallet().map_err(StateError::Db))
    }

    /// Get the wallet owned by the local relayer
    pub fn get_local_relayer_wallet(&self) -> Result<Option<Wallet>, StateError> {
        self.with_blocking_read_tx(|tx| {
            let wallet_id = res_some!(tx.get_local_node_wallet()?);
            let wallet = res_some!(tx.get_wallet(&wallet_id)?);
            Ok(Some(wallet))
        })
    }

    /// Get the decryption key used to settle managed match fees
    pub fn get_fee_key(&self) -> Result<RelayerFeeKey, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_fee_key().map_err(StateError::Db))
    }

    /// Get the local relayer's maximum match fee
    pub fn get_max_relayer_fee(&self) -> Result<FixedPoint, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_max_relayer_fee().map_err(StateError::Db))
    }

    /// Get the relayer fee for a given asset
    pub fn get_relayer_fee(&self, ticker: &str) -> Result<FixedPoint, StateError> {
        let ticker = ticker.to_string(); // Take ownership
        self.with_blocking_read_tx(move |tx| tx.get_relayer_fee(&ticker).map_err(StateError::Db))
    }

    /// Whether atomic matches are supported
    pub fn get_atomic_matches_enabled(&self) -> Result<bool, StateError> {
        let maybe_addr = self.get_external_fee_addr()?;
        Ok(maybe_addr.is_some())
    }

    /// Get the local relayer's external fee address
    pub fn get_external_fee_addr(&self) -> Result<Option<Address>, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_external_fee_addr().map_err(StateError::Db))
    }

    /// Get the local relayer's auto-redeem fees flag
    pub fn get_auto_redeem_fees(&self) -> Result<bool, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_auto_redeem_fees().map_err(StateError::Db))
    }

    /// Get the local relayer's historical state enabled flag
    pub fn historical_state_enabled(&self) -> Result<bool, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_historical_state_enabled().map_err(StateError::Db))
    }

    // -----------
    // | Setters |
    // -----------

    /// Set the known public address of the local peer when discovered
    pub async fn update_local_peer_addr(&self, addr: Multiaddr) -> Result<(), StateError> {
        self.with_write_tx(|tx| {
            // Update the local peer's address in the metadata table
            tx.set_local_addr(&addr)?;
            let peer_id = tx.get_peer_id()?;
            // Update the peer's address in the peer info table
            tx.update_peer_addr(&peer_id, addr)?;
            Ok(())
        })
        .await
    }

    /// Add the local peer's info to the info table
    pub async fn set_local_peer_info(&self, mut info: PeerInfo) -> Result<(), StateError> {
        self.with_write_tx(move |tx| {
            info.successful_heartbeat();
            tx.write_peer(&info)?;
            tx.add_to_cluster(&info.peer_id, &info.cluster_id)?;
            Ok(())
        })
        .await
    }

    /// Set the wallet ID of the local relayer's wallet
    ///
    /// This wallet is managed the same as any other wallet, but we index its ID
    /// here for retrieval
    pub async fn set_local_relayer_wallet_id(
        &self,
        wallet_id: WalletIdentifier,
    ) -> Result<(), StateError> {
        self.with_write_tx(move |tx| {
            tx.set_local_node_wallet(wallet_id)?;
            Ok(())
        })
        .await
    }

    /// Setup the node metadata table from a relayer config
    pub async fn setup_node_metadata(&self, config: &RelayerConfig) -> Result<(), StateError> {
        let peer_id = config.peer_id();
        let cluster_id = config.cluster_id.clone();
        let p2p_key = config.p2p_key.clone();
        let fee_key = config.fee_key;
        let max_match_fee = config.max_match_fee;
        let default_relayer_fee = config.default_match_fee;
        let per_asset_fees = config.per_asset_fees.clone();
        let external_fee_addr = config.external_fee_addr.clone();
        let auto_redeem_fees = config.auto_redeem_fees;

        let need_relayer_wallet = config.needs_relayer_wallet();
        let relayer_wallet_id =
            derive_wallet_id(config.relayer_wallet_key()).map_err(StateError::InvalidUpdate)?;
        let historical_state_enabled = config.record_historical_state;

        if !historical_state_enabled {
            warn!("Historical state is disabled")
        }

        self.with_write_tx(move |tx| {
            tx.create_table(NODE_METADATA_TABLE)?;
            tx.set_peer_id(&peer_id)?;
            tx.set_cluster_id(&cluster_id)?;
            tx.set_node_keypair(&p2p_key)?;
            tx.set_fee_key(&fee_key)?;
            tx.set_max_relayer_fee(&max_match_fee)?;
            tx.set_default_relayer_fee(&default_relayer_fee)?;
            for (ticker, fee) in per_asset_fees.into_iter() {
                tx.set_asset_relayer_fee(&ticker, fee)?;
            }

            tx.set_historical_state_enabled(historical_state_enabled)?;
            if let Some(addr) = external_fee_addr {
                tx.set_external_fee_addr(&addr)?;
            }
            tx.set_auto_redeem_fees(auto_redeem_fees)?;
            if need_relayer_wallet {
                tx.set_local_node_wallet(relayer_wallet_id)?;
            }

            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{mock_relayer_config, mock_state_with_config};

    /// Tests the node metadata setup from a mock config
    #[tokio::test]
    async fn test_node_metadata() {
        // Build the state mock manually to use the generated config
        let config = mock_relayer_config();
        let state = mock_state_with_config(&config).await;

        // Check the metadata fields
        let peer_id = state.get_peer_id().unwrap();
        assert_eq!(peer_id.0, config.p2p_key.public().to_peer_id());

        let cluster_id = state.get_cluster_id().unwrap();
        assert_eq!(cluster_id, config.cluster_id);

        let keypair = state.get_node_keypair().unwrap();
        // Compare bytes
        assert_eq!(
            keypair.to_protobuf_encoding().unwrap(),
            config.p2p_key.to_protobuf_encoding().unwrap()
        );
    }
}
