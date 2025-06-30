//! Handler for the order status topic

use async_trait::async_trait;
use external_api::bus_message::{SystemBusMessage, wallet_order_history_topic};
use state::State;
use system_bus::{SystemBus, TopicReader};

use crate::{
    auth::AuthType,
    error::{ApiServerError, not_found},
    http::parse_wallet_id_from_params,
    router::{ERR_WALLET_NOT_FOUND, UrlParams},
};

use super::handler::WebsocketTopicHandler;

/// The handler for the wallet order status topic
#[derive(Clone)]
pub struct OrderStatusHandler {
    /// A reference to the relayer-global state
    state: State,
    /// A reference to the system bus
    bus: SystemBus<SystemBusMessage>,
}

impl OrderStatusHandler {
    /// Constructor
    pub fn new(state: State, bus: SystemBus<SystemBusMessage>) -> Self {
        Self { state, bus }
    }
}

#[async_trait]
impl WebsocketTopicHandler for OrderStatusHandler {
    /// Handle a new subscription, validate that the wallet is present
    async fn handle_subscribe_message(
        &self,
        _topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        // Parse the wallet ID from the topic captures
        let wallet_id = parse_wallet_id_from_params(route_params)?;

        // If the wallet doesn't exist, throw an error
        if self.state.get_wallet(&wallet_id).await?.is_none() {
            return Err(not_found(ERR_WALLET_NOT_FOUND.to_string()));
        }

        // Subscribe to the topic
        Ok(self.bus.subscribe(wallet_order_history_topic(&wallet_id)))
    }

    /// Does nothing for now, `TopicReader`s clean themselves up
    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }

    fn auth_type(&self) -> AuthType {
        AuthType::Wallet
    }
}
