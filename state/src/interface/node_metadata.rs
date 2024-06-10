//! Stores state information relating to the node's configuration

use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint};
use common::types::{
    gossip::{ClusterId, PeerInfo, WrappedPeerId},
    wallet::{derivation::derive_wallet_id, Wallet, WalletIdentifier},
};
use config::RelayerConfig;
use libp2p::{core::Multiaddr, identity::Keypair};
use util::res_some;

use crate::{error::StateError, State, NODE_METADATA_TABLE};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer ID of the local node
    pub async fn get_peer_id(&self) -> Result<WrappedPeerId, StateError> {
        self.with_read_tx(|tx| tx.get_peer_id().map_err(StateError::Db)).await
    }

    /// Get the cluster ID of the local node
    pub async fn get_cluster_id(&self) -> Result<ClusterId, StateError> {
        self.with_read_tx(|tx| tx.get_cluster_id().map_err(StateError::Db)).await
    }

    /// Get the libp2p keypair of the local node
    pub async fn get_node_keypair(&self) -> Result<Keypair, StateError> {
        self.with_read_tx(|tx| tx.get_node_keypair().map_err(StateError::Db)).await
    }

    /// Get the wallet ID that the local relayer owns
    pub async fn get_relayer_wallet_id(&self) -> Result<WalletIdentifier, StateError> {
        self.with_read_tx(|tx| tx.get_local_node_wallet().map_err(StateError::Db)).await
    }

    /// Get the wallet owned by the local relayer
    pub async fn get_local_relayer_wallet(&self) -> Result<Option<Wallet>, StateError> {
        self.with_read_tx(|tx| {
            let wallet_id = tx.get_local_node_wallet()?;
            let wallet = res_some!(tx.get_wallet(&wallet_id)?);
            Ok(Some(wallet))
        })
        .await
    }

    /// Get the decryption key used to settle managed match fees
    pub async fn get_fee_decryption_key(&self) -> Result<DecryptionKey, StateError> {
        self.with_read_tx(|tx| tx.get_fee_decryption_key().map_err(StateError::Db)).await
    }

    /// Get the local relayer's match take rate
    pub async fn get_relayer_take_rate(&self) -> Result<FixedPoint, StateError> {
        self.with_read_tx(|tx| tx.get_relayer_take_rate().map_err(StateError::Db)).await
    }

    /// Get the relayer fee for a given wallet
    pub async fn get_relayer_fee_for_wallet(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<FixedPoint, StateError> {
        let wid = *wallet_id;
        self.with_read_tx(move |tx| tx.get_relayer_fee(&wid).map_err(StateError::Db)).await
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
        let fee_decryption_key = config.fee_decryption_key;
        let match_take_rate = config.match_take_rate;
        let relayer_fee_whitelist = config.relayer_fee_whitelist.clone();

        let relayer_wallet_id =
            derive_wallet_id(config.relayer_arbitrum_key()).map_err(StateError::InvalidUpdate)?;

        self.with_write_tx(move |tx| {
            tx.create_table(NODE_METADATA_TABLE)?;
            tx.set_peer_id(&peer_id)?;
            tx.set_cluster_id(&cluster_id)?;
            tx.set_node_keypair(&p2p_key)?;
            tx.set_fee_decryption_key(&fee_decryption_key)?;
            tx.set_relayer_take_rate(&match_take_rate)?;
            tx.set_local_node_wallet(relayer_wallet_id)?;

            // Setup the relayer fee whitelist
            for entry in relayer_fee_whitelist {
                let fee = FixedPoint::from_f64_round_down(entry.fee);
                tx.set_relayer_fee(&entry.wallet_id, fee)?;
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
        let peer_id = state.get_peer_id().await.unwrap();
        assert_eq!(peer_id.0, config.p2p_key.public().to_peer_id());

        let cluster_id = state.get_cluster_id().await.unwrap();
        assert_eq!(cluster_id, config.cluster_id);

        let keypair = state.get_node_keypair().await.unwrap();
        // Compare bytes
        assert_eq!(
            keypair.to_protobuf_encoding().unwrap(),
            config.p2p_key.to_protobuf_encoding().unwrap()
        );
    }
}
