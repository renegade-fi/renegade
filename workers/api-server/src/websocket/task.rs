//! Defines handlers for task related websocket routes

// ------------------
// | Error Messages |
// ------------------

use async_trait::async_trait;
use external_api::bus_message::{task_history_topic, task_topic, SystemBusMessage};
use state::State;
use system_bus::{SystemBus, TopicReader};

use crate::{
    auth::AuthType,
    error::{not_found, ApiServerError},
    http::{parse_task_id_from_params, parse_wallet_id_from_params},
    router::UrlParams,
};

use super::handler::WebsocketTopicHandler;

/// Error displayed when the given task cannot be found
const ERR_TASK_MISSING: &str = "task not found";
/// Error message displayed when a wallet cannot be found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

// -----------
// | Handler |
// -----------

/// The handler that manages subscriptions to a task status stream
#[derive(Clone)]
pub struct TaskStatusHandler {
    /// A reference to the global state
    state: State,
    /// A reference to the system bus for subscriptions
    system_bus: SystemBus<SystemBusMessage>,
}

impl TaskStatusHandler {
    /// Constructor
    pub fn new(state: State, system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { state, system_bus }
    }
}

#[async_trait]
impl WebsocketTopicHandler for TaskStatusHandler {
    async fn handle_subscribe_message(
        &self,
        _topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        // Parse the task ID from the route params
        let task_id = parse_task_id_from_params(route_params)?;

        // Check that the task is valid
        if !self.state.contains_task(&task_id).await? {
            return Err(not_found(ERR_TASK_MISSING.to_string()));
        }

        // Subscribe to the topic
        Ok(self.system_bus.subscribe(task_topic(&task_id)))
    }

    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }

    fn auth_type(&self) -> AuthType {
        AuthType::None
    }
}

/// The handler that manages subscriptions to a task history stream
#[derive(Clone)]
pub struct TaskHistoryHandler {
    /// A reference to the global state
    state: State,
    /// A reference to the system bus for subscriptions
    system_bus: SystemBus<SystemBusMessage>,
}

impl TaskHistoryHandler {
    /// Constructor
    pub fn new(state: State, system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { state, system_bus }
    }
}

#[async_trait]
impl WebsocketTopicHandler for TaskHistoryHandler {
    async fn handle_subscribe_message(
        &self,
        _topic: String,
        route_params: &UrlParams,
    ) -> Result<TopicReader<SystemBusMessage>, ApiServerError> {
        // Parse the wallet ID from the route params
        let wallet_id = parse_wallet_id_from_params(route_params)?;

        // Check that the wallet is valid
        if !self.state.contains_wallet(&wallet_id).await? {
            return Err(not_found(ERR_WALLET_NOT_FOUND.to_string()));
        }

        // Subscribe to the topic
        Ok(self.system_bus.subscribe(task_history_topic(&wallet_id)))
    }

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
