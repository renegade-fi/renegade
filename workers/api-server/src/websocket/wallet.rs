//! Handler definitions for wallet websocket topics
use async_trait::async_trait;
use external_api::bus_message::{wallet_topic_name, SystemBusMessage};
use state::RelayerState;
use system_bus::{SystemBus, TopicReader};

use crate::{
    error::{not_found, ApiServerError},
    http::parse_wallet_id_from_params,
    router::UrlParams,
};

use super::handler::WebsocketTopicHandler;

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a wallet is not found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

// -----------
// | Handler |
// -----------

/// The handler for the wallet update websocket topic
#[derive(Clone)]
pub struct WalletTopicHandler {
    /// A copy of the relayer global state
    global_state: RelayerState,
    /// A reference to the relayer global system bus
    system_bus: SystemBus<SystemBusMessage>,
}

impl WalletTopicHandler {
    /// Constructor
    pub fn new(global_state: RelayerState, system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { global_state, system_bus }
    }
}

#[async_trait]
impl WebsocketTopicHandler for WalletTopicHandler {
    /// Handle a new subscription, validate that the wallet is present
    async fn handle_subscribe_message(
        &self,
        _topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        // Parse the wallet ID from the topic captures
        let wallet_id = parse_wallet_id_from_params(route_params)?;

        // If the wallet doesn't exist, throw an error
        if self.global_state.read_wallet_index().await.get_wallet(&wallet_id).await.is_none() {
            return Err(not_found(ERR_WALLET_NOT_FOUND.to_string()));
        }

        // Subscribe to the topic
        Ok(self.system_bus.subscribe(wallet_topic_name(&wallet_id)))
    }

    /// Does nothing for now, `TopicReader`s clean themselves up
    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }

    fn requires_wallet_auth(&self) -> bool {
        true
    }
}
