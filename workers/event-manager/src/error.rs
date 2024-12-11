//! Defines errors for the event manager

/// An error that occurred in the event manager
#[derive(Clone, Debug)]
pub enum EventManagerError {
    /// The event manager was cancelled
    Cancelled(String),
    /// The event export address is invalid
    InvalidEventExportAddr(String),
    /// An error occurred while connecting to the event export socket
    SocketConnection(String),
    /// An error occurred while serializing an event
    Serialize(String),
    /// An error occurred while writing to the event export socket
    SocketWrite(String),
    /// An error occurred while setting up the event manager
    SetupError(String),
}
