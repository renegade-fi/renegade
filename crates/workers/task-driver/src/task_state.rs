//! Task state management

use std::fmt::Display;

use serde::Serialize;
use types_tasks::QueuedTaskState;

// --------------------
// | State Management |
// --------------------

/// Defines a wrapper that allows state objects to be stored generically
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "task_type", content = "state")]
pub enum StateWrapper {}

impl StateWrapper {
    /// Whether the underlying state is committed or not
    pub fn committed(&self) -> bool {
        match self {
            _ => todo!("implement committed for {self:?}"),
        }
    }

    /// Whether or not this state commits the task, i.e. is the first state that
    /// for which `committed` is true
    pub fn is_committing(&self) -> bool {
        match self {
            _ => todo!("implement is_committing for {self:?}"),
        }
    }

    /// Whether the underlying state is completed or not
    pub fn completed(&self) -> bool {
        match self {
            _ => todo!("implement completed for {self:?}"),
        }
    }
}

impl Display for StateWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            _ => todo!("implement display for {self:?}"),
        };
        write!(f, "{out}")
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
