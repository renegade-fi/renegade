//! Task state management

use std::fmt::Display;

use serde::Serialize;
use types_tasks::QueuedTaskState;

use crate::{
    tasks::{create_new_account::CreateNewAccountTaskState, node_startup::NodeStartupTaskState},
    traits::TaskState,
};

// --------------------
// | State Management |
// --------------------

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum StateWrapper {
    /// The state of a create new account task
    CreateNewAccount(CreateNewAccountTaskState),
    /// The state of a node startup task
    NodeStartup(NodeStartupTaskState),
}

impl StateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            StateWrapper::CreateNewAccount(state) => {
                <CreateNewAccountTaskState as TaskState>::committed(state)
            },
            StateWrapper::NodeStartup(state) => {
                <NodeStartupTaskState as TaskState>::committed(state)
            },
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            StateWrapper::CreateNewAccount(state) => {
                *state == CreateNewAccountTaskState::commit_point()
            },
            StateWrapper::NodeStartup(state) => *state == NodeStartupTaskState::commit_point(),
        }
    }

    /// Whether the underlying state is completed or not
    pub fn completed(&self) -> bool {
        match self {
            StateWrapper::CreateNewAccount(state) => {
                <CreateNewAccountTaskState as TaskState>::completed(state)
            },
            StateWrapper::NodeStartup(state) => {
                <NodeStartupTaskState as TaskState>::completed(state)
            },
        }
    }
}

impl Display for StateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateWrapper::CreateNewAccount(state) => write!(f, "{state}"),
            StateWrapper::NodeStartup(state) => write!(f, "{state}"),
        }
    }
}

impl From<StateWrapper> for QueuedTaskState {
    fn from(value: StateWrapper) -> Self {
        // Serialize the state into a string
        let description = value.to_string();
        let committed = value.committed();
        QueuedTaskState::Running { state: description, committed }
    }
}
