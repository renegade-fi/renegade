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
        for peer in self
            .global_state
            .get_local_cluster_peers(false /* include_self */)
            .await
        {
            self.handle_outbound_message(GossipOutbound::Request {
                peer_id: peer,
                message: GossipRequest::WalletUpdate {
                    wallet: wallet.clone(),
                },
            })?;
        }

        Ok(())
    }
}
