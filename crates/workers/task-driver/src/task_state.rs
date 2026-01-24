//! Task state management

use std::fmt::Display;

use serde::Serialize;
use types_tasks::QueuedTaskState;

use crate::{
    tasks::{
        create_balance::CreateBalanceTaskState, create_new_account::CreateNewAccountTaskState,
        create_order::CreateOrderTaskState, deposit::DepositTaskState,
        node_startup::NodeStartupTaskState,
        settle_external_match::SettleExternalMatchTaskState,
        settle_internal_match::SettleInternalMatchTaskState,
    },
    traits::TaskState,
};

// --------------------
// | State Management |
// --------------------

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum TaskStateWrapper {
    /// The state of a create new account task
    CreateNewAccount(CreateNewAccountTaskState),
    /// The state of a node startup task
    NodeStartup(NodeStartupTaskState),
    /// The state of a deposit task
    Deposit(DepositTaskState),
    /// The state of a create balance task
    CreateBalance(CreateBalanceTaskState),
    /// The state of a create order task
    CreateOrder(CreateOrderTaskState),
    /// The state of a settle internal match task
    SettleInternalMatch(SettleInternalMatchTaskState),
    /// The state of a settle external match task
    SettleExternalMatch(SettleExternalMatchTaskState),
}

impl TaskStateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            TaskStateWrapper::CreateNewAccount(state) => {
                <CreateNewAccountTaskState as TaskState>::committed(state)
            },
            TaskStateWrapper::NodeStartup(state) => {
                <NodeStartupTaskState as TaskState>::committed(state)
            },
            TaskStateWrapper::Deposit(state) => <DepositTaskState as TaskState>::committed(state),
            TaskStateWrapper::CreateBalance(state) => {
                <CreateBalanceTaskState as TaskState>::committed(state)
            },
            TaskStateWrapper::CreateOrder(state) => {
                <CreateOrderTaskState as TaskState>::committed(state)
            },
            TaskStateWrapper::SettleInternalMatch(state) => {
                <SettleInternalMatchTaskState as TaskState>::committed(state)
            },
            TaskStateWrapper::SettleExternalMatch(state) => {
                <SettleExternalMatchTaskState as TaskState>::committed(state)
            },
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            TaskStateWrapper::CreateNewAccount(state) => {
                *state == CreateNewAccountTaskState::commit_point()
            },
            TaskStateWrapper::NodeStartup(state) => *state == NodeStartupTaskState::commit_point(),
            TaskStateWrapper::Deposit(state) => *state == DepositTaskState::commit_point(),
            TaskStateWrapper::CreateBalance(state) => {
                *state == CreateBalanceTaskState::commit_point()
            },
            TaskStateWrapper::CreateOrder(state) => *state == CreateOrderTaskState::commit_point(),
            TaskStateWrapper::SettleInternalMatch(state) => {
                *state == SettleInternalMatchTaskState::commit_point()
            },
            TaskStateWrapper::SettleExternalMatch(state) => {
                *state == SettleExternalMatchTaskState::commit_point()
            },
        }
    }

    /// Whether the underlying state is completed or not
    pub fn completed(&self) -> bool {
        match self {
            TaskStateWrapper::CreateNewAccount(state) => {
                <CreateNewAccountTaskState as TaskState>::completed(state)
            },
            TaskStateWrapper::NodeStartup(state) => {
                <NodeStartupTaskState as TaskState>::completed(state)
            },
            TaskStateWrapper::Deposit(state) => <DepositTaskState as TaskState>::completed(state),
            TaskStateWrapper::CreateBalance(state) => {
                <CreateBalanceTaskState as TaskState>::completed(state)
            },
            TaskStateWrapper::CreateOrder(state) => {
                <CreateOrderTaskState as TaskState>::completed(state)
            },
            TaskStateWrapper::SettleInternalMatch(state) => {
                <SettleInternalMatchTaskState as TaskState>::completed(state)
            },
            TaskStateWrapper::SettleExternalMatch(state) => {
                <SettleExternalMatchTaskState as TaskState>::completed(state)
            },
        }
    }
}

impl Display for TaskStateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStateWrapper::CreateNewAccount(state) => write!(f, "{state}"),
            TaskStateWrapper::NodeStartup(state) => write!(f, "{state}"),
            TaskStateWrapper::Deposit(state) => write!(f, "{state}"),
            TaskStateWrapper::CreateBalance(state) => write!(f, "{state}"),
            TaskStateWrapper::CreateOrder(state) => write!(f, "{state}"),
            TaskStateWrapper::SettleInternalMatch(state) => write!(f, "{state}"),
            TaskStateWrapper::SettleExternalMatch(state) => write!(f, "{state}"),
        }
    }
}

impl From<TaskStateWrapper> for QueuedTaskState {
    fn from(value: TaskStateWrapper) -> Self {
        // Serialize the state into a string
        let description = value.to_string();
        let committed = value.committed();
        QueuedTaskState::Running { state: description, committed }
    }
}
