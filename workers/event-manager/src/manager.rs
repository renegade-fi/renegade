//! The core event manager logic, the main loop that receives events
//! and exports them to the configured address

use std::{path::Path, thread::JoinHandle};

use common::types::CancelChannel;
use constants::in_bootstrap_mode;
use job_types::event_manager::EventManagerReceiver;
use libp2p::{multiaddr::Protocol, Multiaddr};
use tokio::{io::AsyncWriteExt, net::UnixStream};
use tracing::{info, warn};
use util::{err_str, runtime::sleep_forever_async};

use crate::{error::EventManagerError, worker::EventManagerConfig};

// -------------
// | Constants |
// -------------

/// The error message for when the event export address is not a Unix socket
const ERR_NON_UNIX_EVENT_EXPORT_ADDRESS: &str =
    "Only Unix socket event export addresses are currently supported";

// ----------------------
// | Manager / Executor |
// ----------------------

/// The event manager worker
pub struct EventManager {
    /// The event manager executor
    pub executor: Option<EventManagerExecutor>,
    /// The handle on the event manager
    pub handle: Option<JoinHandle<EventManagerError>>,
}

/// Manages the exporting of events to the configured address
pub struct EventManagerExecutor {
    /// The channel on which to receive events
    event_queue: EventManagerReceiver,
    /// The address to export relayer events to
    event_export_addr: Option<Multiaddr>,
    /// The channel on which the coordinator may cancel event manager execution
    cancel_channel: CancelChannel,
}

impl EventManagerExecutor {
    /// Constructs a new event manager executor
    pub fn new(config: EventManagerConfig) -> Self {
        let EventManagerConfig { event_queue, event_export_addr, cancel_channel } = config;

        Self { event_queue, event_export_addr, cancel_channel }
    }

    /// Constructs the export sink for the event manager.
    ///
    /// Currently, only Unix socket export addresses are supported.
    pub async fn construct_export_sink(&mut self) -> Result<Option<UnixStream>, EventManagerError> {
        if self.event_export_addr.is_none() {
            return Ok(None);
        }

        let mut event_export_addr = self.event_export_addr.take().unwrap();
        let unix_path =
            match event_export_addr.pop().expect("event export address must not be empty") {
                Protocol::Unix(path) => path.to_string(),
                _ => {
                    return Err(EventManagerError::InvalidEventExportAddr(
                        ERR_NON_UNIX_EVENT_EXPORT_ADDRESS.to_string(),
                    ))
                },
            };

        let socket = UnixStream::connect(Path::new(&unix_path))
            .await
            .map_err(err_str!(EventManagerError::SocketConnection))?;

        Ok(Some(socket))
    }

    /// The main execution loop; receives events and exports them to the
    /// configured sink
    pub async fn execution_loop(mut self) -> Result<(), EventManagerError> {
        // If the node is running in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        let disabled = self.event_export_addr.is_none();
        let mut sink = self.construct_export_sink().await?;

        loop {
            tokio::select! {
                Some(event) = self.event_queue.recv() => {
                    if disabled {
                        warn!("EventManager received event while disabled, ignoring...");
                        continue;
                    }

                    let sink = sink.as_mut().unwrap();
                    let event_bytes = serde_json::to_vec(&event).map_err(err_str!(EventManagerError::Serialize))?;
                    sink.write_all(&event_bytes).await.map_err(err_str!(EventManagerError::SocketWrite))?;
                },

                _ = self.cancel_channel.changed() => {
                    info!("EventManager received cancel signal, shutting down...");
                    return Err(EventManagerError::Cancelled("received cancel signal".to_string()));
                }
            }
        }
    }
}
