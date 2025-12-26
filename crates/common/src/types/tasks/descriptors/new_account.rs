//! Descriptor for the new account task

use serde::{Deserialize, Serialize};

use crate::types::AccountId;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the `NewAccount`
/// task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewAccountTaskDescriptor {
    /// The account ID to create
    pub account_id: AccountId,
}

impl From<NewAccountTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: NewAccountTaskDescriptor) -> Self {
        TaskDescriptor::NewAccount(descriptor)
    }
}
