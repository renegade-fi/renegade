//! Simulates the effect of tasks on the relayer state

mod account_tasks;
pub mod error;
pub mod oracle;

pub use account_tasks::{SimulationReport, simulate_account_tasks};
