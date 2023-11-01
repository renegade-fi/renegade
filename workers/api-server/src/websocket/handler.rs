//! Defines handles for websocket routes
//!
//! Most websocket routes are fairly straightforward, they simply subscribe
//! to the relevant topic on the system bus. However, the price reporting and
//! potential future extensions require logic executed per connection
//!
//! Plus, this more closely follows the practice taken in the HTTP router

use async_trait::async_trait;
use external_api::bus_message::SystemBusMessage;
use system_bus::{SystemBus, TopicReader};

use crate::{error::ApiServerError, router::UrlParams};

/// The main trait that route handlers implement for their topic, handles any
/// custom logic required to process a websocket subscribe/unsubscribe request
#[async_trait]
pub trait WebsocketTopicHandler: Send + Sync {
    /// Handle a request to subscribe to the topic
    async fn handle_subscribe_message(
        &self,
        topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError>;
    /// Handle a request to unsubscribe from a topic
    async fn handle_unsubscribe_message(
        &self,
        topic: String,
        route_params: &UrlParams,
    ) -> Result<(), ApiServerError>;

    /// Whether or not the route requires wallet auth
    fn requires_wallet_auth(&self) -> bool;
}

/// The default handler directly subscribes and unsubscribes from the topic
#[derive(Clone)]
pub struct DefaultHandler {
    /// Whether or not the endpoint is authenticated
    authenticated: bool,
    /// A reference to the relayer-global system bus
    system_bus: SystemBus<SystemBusMessage>,
    /// The bus topic to subscribe to on a subscription message
    ///
    /// Defaults to the topic subscribed to at the router layer
    topic_remap: Option<String>,
}

impl DefaultHandler {
    /// Constructor
    pub fn new_with_remap(
        authenticated: bool,
        topic_remap: String,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self {
            authenticated,
            system_bus,
            topic_remap: Some(topic_remap),
        }
    }
}

#[async_trait]
impl WebsocketTopicHandler for DefaultHandler {
    /// Handle a subscription by simply allocating a reader on the topic
    async fn handle_subscribe_message(
        &self,
        topic: String,
        _route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        let bus_topic = match self.topic_remap {
            Some(ref remap) => remap.clone(),
            None => topic,
        };

        Ok(self.system_bus.subscribe(bus_topic))
    }

    /// Unsubscribe does nothing, `TopicReader`s handle their own cleanup
    /// when they are dropped, so no extra cleanup needs to be done
    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }

    fn requires_wallet_auth(&self) -> bool {
        self.authenticated
    }
}
