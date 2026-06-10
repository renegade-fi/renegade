//! Stores state information relating to the node's configuration

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use circuit_types::fixed_point::FixedPoint;
use config::RelayerConfig;
use libp2p::{core::Multiaddr, identity::Keypair};
use types_gossip::{ClusterId, PeerInfo, WrappedPeerId};
use util::log_task;
use util::logging::Outcome;

use crate::{NODE_METADATA_TABLE, StateInner, error::StateError, logging::Task};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Get the peer ID of the local node
    pub fn get_peer_id(&self) -> Result<WrappedPeerId, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_peer_id().map_err(StateError::Db))
    }

    /// Get the cluster ID of the local node
    ///
    /// Served from cached boot config (`StateConfig`) so the hot request path
    /// (e.g. `/v2/network`) does not open an inline MDBX read tx on an
    /// api-server worker thread.
    pub fn get_cluster_id(&self) -> Result<ClusterId, StateError> {
        Ok(self.config.cluster_id.clone())
    }

    /// Get the libp2p keypair of the local node
    pub fn get_node_keypair(&self) -> Result<Keypair, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_node_keypair().map_err(StateError::Db))
    }

    /// Get the local relayer's maximum match fee
    pub fn get_max_relayer_fee(&self) -> Result<FixedPoint, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_max_relayer_fee().map_err(StateError::Db))
    }

    /// Get the relayer fee for a given asset
    ///
    /// Served from cached boot config; a per-ticker override falling back to
    /// the default fee, matching the on-disk `tx.get_relayer_fee`
    /// semantics.
    pub fn get_relayer_fee(&self, ticker: &str) -> Result<FixedPoint, StateError> {
        Ok(self
            .config
            .per_asset_fees
            .get(ticker)
            .copied()
            .unwrap_or(self.config.default_relayer_fee))
    }

    /// Get the local relayer's fee address
    ///
    /// Served from cached boot config (see `get_cluster_id`).
    pub fn get_relayer_fee_addr(&self) -> Result<Address, StateError> {
        Ok(self.config.relayer_fee_addr)
    }

    /// Get the local relayer's historical state enabled flag
    pub fn historical_state_enabled(&self) -> Result<bool, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_historical_state_enabled().map_err(StateError::Db))
    }

    /// Get the executor private key
    pub fn get_executor_key(&self) -> Result<PrivateKeySigner, StateError> {
        self.with_blocking_read_tx(|tx| tx.get_executor_key().map_err(StateError::Db))
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

    /// Setup the node metadata table from a relayer config
    pub async fn setup_node_metadata(&self, config: &RelayerConfig) -> Result<(), StateError> {
        let peer_id = config.peer_id();
        let cluster_id = config.cluster_id.clone();
        let p2p_key = config.p2p_key.clone();
        let max_match_fee = config.max_match_fee;
        let default_relayer_fee = config.default_match_fee;
        let per_asset_fees = config.per_asset_fees.clone();
        let relayer_fee_addr = config.relayer_fee_addr;
        let historical_state_enabled = config.record_historical_state;
        let executor_key = config.executor_private_key.clone();

        if !historical_state_enabled {
            log_task!(Task::NodeSetup, Outcome::Partial, "historical state is disabled");
        }

        self.with_write_tx(move |tx| {
            tx.create_table(NODE_METADATA_TABLE)?;
            tx.set_peer_id(&peer_id)?;
            tx.set_cluster_id(&cluster_id)?;
            tx.set_node_keypair(&p2p_key)?;
            tx.set_max_relayer_fee(&max_match_fee)?;
            tx.set_default_relayer_fee(&default_relayer_fee)?;
            for (ticker, fee) in per_asset_fees.into_iter() {
                tx.set_asset_relayer_fee(&ticker, fee)?;
            }

            tx.set_historical_state_enabled(historical_state_enabled)?;
            tx.set_relayer_fee_addr(&relayer_fee_addr)?;
            tx.set_executor_key(&executor_key)?;

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

    /// Validate the cached node-metadata getters (Fix 3, Edit 1):
    /// `get_cluster_id`, `get_relayer_fee_addr`, and `get_relayer_fee` are
    /// served from the cached `StateConfig` (no inline MDBX read on the
    /// api-server worker thread), and the per-ticker override / default
    /// fallback matches the on-disk semantics.
    #[tokio::test]
    async fn test_cached_node_metadata_getters() {
        use std::time::Duration;

        use alloy_primitives::Address;
        use circuit_types::fixed_point::FixedPoint;

        let mut config = mock_relayer_config();
        config.relayer_fee_addr = Address::from([7u8; 20]);
        config.default_match_fee = FixedPoint::from_f64_round_down(0.002);
        let override_fee = FixedPoint::from_f64_round_down(0.001);
        config.per_asset_fees.insert("WETH".to_string(), override_fee);

        // Timeout-guard: `mock_state_with_config` spins a mock raft; never let the
        // test itself hang (mock_state raft stalls at high concurrency).
        let state = tokio::time::timeout(Duration::from_secs(60), mock_state_with_config(&config))
            .await
            .expect("mock state setup timed out");

        // All three getters resolve from the cached StateConfig.
        assert_eq!(state.get_cluster_id().unwrap(), config.cluster_id);
        assert_eq!(state.get_relayer_fee_addr().unwrap(), config.relayer_fee_addr);
        // Per-ticker override resolves to the configured value...
        assert_eq!(state.get_relayer_fee("WETH").unwrap(), override_fee);
        // ...and an unknown ticker falls back to the default fee.
        assert_eq!(state.get_relayer_fee("NOPE").unwrap(), config.default_match_fee);
    }
}
