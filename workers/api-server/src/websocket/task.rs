//! Defines handlers for task related websocket routes

// ------------------
// | Error Messages |
// ------------------

use async_trait::async_trait;
use external_api::bus_message::{task_topic_name, SystemBusMessage};
use system_bus::{SystemBus, TopicReader};
use task_driver::driver::TaskDriver;

use crate::{
    error::{not_found, ApiServerError},
    http::parse_task_id_from_params,
    router::UrlParams,
};

use super::handler::WebsocketTopicHandler;

/// Error displayed when the given task cannot be found
const ERR_TASK_MISSING: &str = "task not found";

// -----------
// | Handler |
// -----------

/// The handler that manages subscriptions to a task status stream
#[derive(Clone)]
pub struct TaskStatusHandler {
    /// A reference to the task driver that holds statuses
    task_driver: TaskDriver,
    /// A reference to the system bus for subscriptions
    system_bus: SystemBus<SystemBusMessage>,
}

impl TaskStatusHandler {
    /// Constructor
    pub fn new(task_driver: TaskDriver, system_bus: SystemBus<SystemBusMessage>) -> Self {
        Self { task_driver, system_bus }
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
        if !self.task_driver.contains_task(&task_id).await {
            return Err(not_found(ERR_TASK_MISSING.to_string()));
        }

        // Subscribe to the topic
        Ok(self.system_bus.subscribe(task_topic_name(&task_id)))
    }

    async fn handle_unsubscribe_message(
        &self,
        _topic: String,
        _route_params: &UrlParams,
    ) -> Result<(), ApiServerError> {
        Ok(())
    }

    fn requires_wallet_auth(&self) -> bool {
        false
    }
}
