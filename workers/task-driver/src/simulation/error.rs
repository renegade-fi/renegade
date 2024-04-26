//! Error type for the task simulator

use std::error::Error;
use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// The error type emitted during task simulation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaskSimulationError {
    /// An invalid task was provided to the simulator
    InvalidTask(&'static str),
    /// Invalid wallet state to apply a transition
    InvalidWalletState(&'static str),
}

impl Display for TaskSimulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TaskSimulationError {}
