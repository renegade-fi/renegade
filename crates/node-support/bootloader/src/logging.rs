//! The closed `Task` vocabulary for the bootloader binary's structured logs.
//!
//! Each variant names one operation the bootloader performs. See
//! [`util::logging`] for the envelope shape and [`util::log_task`] for the
//! macro that emits these.

use util::logging::LogTask;

/// The set of operations the bootloader binary performs, used as the `task`
/// dimension of its structured logs.
pub(crate) enum Task {
    /// Registering the relayer's gas wallet with the funds manager.
    GasWalletRegistration,
    /// Downloading the latest relayer snapshot from S3.
    SnapshotDownload,
    /// Supervising the spawned sidecar and relayer child processes.
    SidecarSupervision,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::GasWalletRegistration => "gas-wallet-registration",
            Task::SnapshotDownload => "snapshot-download",
            Task::SidecarSupervision => "sidecar-supervision",
        }
    }
}
