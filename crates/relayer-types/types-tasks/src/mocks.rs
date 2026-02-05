//! Mock types for testing

use darkpool_types::fuzzing::random_address;
use types_account::account::mocks::mock_keychain;

use crate::{NewAccountTaskDescriptor, QueuedTask, TaskDescriptor, TaskQueueKey};

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
