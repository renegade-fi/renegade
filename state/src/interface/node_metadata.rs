//! Stores state information relating to the node's configuration

use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint};
use common::types::{
    gossip::{ClusterId, PeerInfo, WrappedPeerId},
    wallet::{Wallet, WalletIdentifier},
};
use config::RelayerConfig;
use libp2p::{core::Multiaddr, identity::Keypair};
use util::res_some;

use crate::{
    error::StateError, replicationv2::raft::NetworkEssential, State, StateHandle,
    NODE_METADATA_TABLE,
};

impl<N: NetworkEssential> StateHandle<N> {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer ID of the local node
    pub fn get_peer_id(&self) -> Result<WrappedPeerId, StateError> {
        let tx = self.db.new_read_tx()?;
        let peer_id = tx.get_peer_id()?;
        tx.commit()?;

        Ok(peer_id)
    }

    /// Get the cluster ID of the local node
    pub fn get_cluster_id(&self) -> Result<ClusterId, StateError> {
        let tx = self.db.new_read_tx()?;
        let cluster_id = tx.get_cluster_id()?;
        tx.commit()?;

        Ok(cluster_id)
    }

    /// Get the libp2p keypair of the local node
    pub fn get_node_keypair(&self) -> Result<Keypair, StateError> {
        let tx = self.db.new_read_tx()?;
        let keypair = tx.get_node_keypair()?;
        tx.commit()?;

        Ok(keypair)
    }

    /// Get the wallet ID that the local relayer owns
    pub fn get_relayer_wallet_id(&self) -> Result<Option<WalletIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet_id = tx.get_local_node_wallet()?;
        tx.commit()?;

        Ok(Some(wallet_id))
    }

    /// Get the wallet owned by the local relayer
    pub fn get_local_relayer_wallet(&self) -> Result<Option<Wallet>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet_id = tx.get_local_node_wallet()?;
        let wallet = res_some!(tx.get_wallet(&wallet_id)?);
        tx.commit()?;

        Ok(Some(wallet))
    }

    /// Get the decryption key used to settle managed match fees
    pub fn get_fee_decryption_key(&self) -> Result<DecryptionKey, StateError> {
        let tx = self.db.new_read_tx()?;
        let key = tx.get_fee_decryption_key()?;
        tx.commit()?;

        Ok(key)
    }

    /// Get the local relayer's match take rate
    pub fn get_relayer_take_rate(&self) -> Result<FixedPoint, StateError> {
        let tx = self.db.new_read_tx()?;
        let rate = tx.get_relayer_take_rate()?;
        tx.commit()?;

        Ok(rate)
    }

    // -----------
    // | Setters |
    // -----------

    /// Set the known public address of the local peer when discovered
    pub fn update_local_peer_addr(&self, addr: Multiaddr) -> Result<(), StateError> {
        let tx = self.db.new_write_tx()?;
        // Update the local peer's address in the metadata table
        tx.set_local_addr(&addr)?;
        let peer_id = tx.get_peer_id()?;
        // Update the peer's address in the peer info table
        tx.update_peer_addr(&peer_id, addr)?;
        Ok(tx.commit()?)
    }

    /// Add the local peer's info to the info table
    pub fn set_local_peer_info(&self, mut info: PeerInfo) -> Result<(), StateError> {
        let tx = self.db.new_write_tx()?;

        info.successful_heartbeat();
        tx.write_peer(&info)?;
        tx.add_to_cluster(&info.peer_id, &info.cluster_id)?;

        Ok(tx.commit()?)
    }

    /// Set the wallet ID of the local relayer's wallet
    ///
    /// This wallet is managed the same as any other wallet, but we index its ID
    /// here for retrieval
    pub fn set_local_relayer_wallet_id(
        &self,
        wallet_id: WalletIdentifier,
    ) -> Result<(), StateError> {
        let tx = self.db.new_write_tx()?;
        tx.set_local_node_wallet(wallet_id)?;
        Ok(tx.commit()?)
    }

    /// Setup the node metadata table from a relayer config
    pub fn setup_node_metadata(&self, config: &RelayerConfig) -> Result<(), StateError> {
        let keypair = &config.p2p_key;
        let peer_id = WrappedPeerId(keypair.public().to_peer_id());

        let tx = self.db.new_write_tx()?;
        tx.create_table(NODE_METADATA_TABLE)?;
        tx.set_peer_id(&peer_id)?;
        tx.set_cluster_id(&config.cluster_id)?;
        tx.set_node_keypair(&config.p2p_key)?;
        tx.set_fee_decryption_key(&config.fee_decryption_key)?;
        tx.set_relayer_take_rate(&config.match_take_rate)?;

        tx.commit()?;
        Ok(())
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
