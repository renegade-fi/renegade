//! Defines errors for the event manager

use thiserror::Error;

/// An error that occurred in the event manager
#[derive(Clone, Debug, Error)]
pub enum EventManagerError {
    /// The event manager was cancelled
    #[error("event manager cancelled: {0}")]
    Cancelled(String),
    /// The event export address is invalid
    #[error("invalid event export address: {0}")]
    InvalidEventExportAddr(String),
    /// An error occurred while connecting to the event export socket
    #[error("error connecting to event export socket: {0}")]
    SocketConnection(String),
    /// An error occurred while serializing an event
    #[error("error serializing event: {0}")]
    Serialize(String),
    /// An error occurred while writing to the event export socket
    #[error("error writing to event export socket: {0}")]
    SocketWrite(String),
    /// An error occurred while setting up the event manager
    #[error("error setting up event manager: {0}")]
    SetupError(String),
}
