//! Groups worker job types to expose them as a third party crate to the workers

pub mod gossip_server;
pub mod handshake_manager;
pub mod network_manager;
pub mod price_reporter;
pub mod proof_manager;
pub mod task_driver;

use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

/// A response channel sender
pub type ResponseSender<T> = OneshotSender<T>;
/// A response channel receiver
pub type ResponseReceiver<T> = OneshotReceiver<T>;

/// Create a new response channel for a request
pub fn new_response_channel<T>() -> (ResponseSender<T>, ResponseReceiver<T>) {
    oneshot_channel()
}
