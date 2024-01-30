//! Stores state information relating to the node's configuration

use common::types::gossip::{ClusterId, PeerInfo, WrappedPeerId};
use config::RelayerConfig;
use libp2p::{core::Multiaddr, identity::Keypair};

use crate::{error::StateError, State, NODE_METADATA_TABLE};

impl State {
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

    // -----------
    // | Setters |
    // -----------

    /// Set the known public address of the local peer when discovered
    pub fn update_local_peer_addr(&self, addr: &Multiaddr) -> Result<(), StateError> {
        let tx = self.db.new_write_tx()?;
        tx.set_local_addr(addr)?;
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

    /// Setup the node metadata table from a relayer config
    pub fn setup_node_metadata(&self, config: &RelayerConfig) -> Result<(), StateError> {
        let keypair = &config.p2p_key;
        let peer_id = WrappedPeerId(keypair.public().to_peer_id());

        let tx = self.db.new_write_tx()?;
        tx.create_table(NODE_METADATA_TABLE)?;
        tx.set_peer_id(&peer_id)?;
        tx.set_cluster_id(&config.cluster_id)?;
        tx.set_node_keypair(&config.p2p_key)?;

        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use config::RelayerConfig;
    use system_bus::SystemBus;

    use crate::{replication::network::test_helpers::MockNetwork, State};

    /// Tests the node metadata setup from a mock config
    #[test]
    fn test_node_metadata() {
        // Build the state mock manually to use the generated config
        let config = RelayerConfig::default();
        let network = MockNetwork::new_n_way_mesh(1 /* n_nodes */).remove(0);
        let bus = SystemBus::new();
        let state = State::new(&config, network, bus).unwrap();

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
