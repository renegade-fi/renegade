//! Defines handlers for events originating from other workers in the relayer

use common::types::wallet::Wallet;
use gossip_api::gossip::{GossipOutbound, GossipRequest};

use crate::error::NetworkManagerError;

use super::NetworkManagerExecutor;

impl NetworkManagerExecutor {
    /// Handle a wallet update event streamed from the system bus
    pub(crate) async fn handle_wallet_update(
        &mut self,
        wallet: Box<Wallet>,
    ) -> Result<(), NetworkManagerError> {
        // Gossip the new wallet to all cluster peers
        let my_peer_id = self.global_state.get_peer_id()?;
        let cluster_id = self.global_state.get_cluster_id()?;
        for peer_id in self.global_state.get_cluster_peers(&cluster_id)? {
            if peer_id == my_peer_id {
                continue;
            }

            self.handle_outbound_message(GossipOutbound::Request {
                peer_id,
                message: GossipRequest::WalletUpdate { wallet: wallet.clone() },
            })?;
        }

        Ok(())
    }
}
