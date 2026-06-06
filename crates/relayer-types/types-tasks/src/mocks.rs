//! Mock types for testing

use darkpool_types::fuzzing::random_address;
use types_account::{
    OrderId,
    account::mocks::{mock_intent, mock_keychain},
    order::{OrderMetadata, PrivacyRing},
    order_auth::mocks::mock_order_auth,
};

use crate::{
    CreateOrderTaskDescriptor, NewAccountTaskDescriptor, QueuedTask, TaskDescriptor, TaskQueueKey,
};

/// Create a mock queued task
pub fn mock_queued_task(key: TaskQueueKey) -> QueuedTask {
    let descriptor = mock_task_descriptor(key);
    QueuedTask::new(descriptor)
}

/// Create a mock task descriptor
pub fn mock_task_descriptor(key: TaskQueueKey) -> TaskDescriptor {
    TaskDescriptor::NewAccount(NewAccountTaskDescriptor {
        account_id: key,
        keychain: mock_keychain(),
        owner_address: random_address(),
    })
}

/// Create a mock YIELDABLE (`CreateOrder`) queued task, for order-yield tests.
///
/// `is_yieldable()` only inspects the descriptor variant, so the field values
/// are placeholders.
pub fn mock_create_order_task(key: TaskQueueKey) -> QueuedTask {
    let descriptor = TaskDescriptor::CreateOrder(CreateOrderTaskDescriptor {
        account_id: key,
        order_id: OrderId::new_v4(),
        intent: mock_intent(),
        ring: PrivacyRing::Ring0,
        metadata: OrderMetadata::default(),
        auth: mock_order_auth(),
        matching_pool: String::new(),
    });
    QueuedTask::new(descriptor)
}
