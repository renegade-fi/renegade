//! The core event manager logic, the main loop that receives events
//! and exports them to the configured address

use std::{path::Path, thread::JoinHandle};

use common::types::{chain::Chain, CancelChannel};
use constants::in_bootstrap_mode;
use futures::sink::SinkExt;
use job_types::event_manager::{EventManagerReceiver, RelayerEvent, RelayerEventType};
use renegade_metrics::labels::NUM_EVENT_EXPORT_FAILURES_METRIC;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};
use tracing::{error, info, warn};
use url::Url;
use util::{concurrency::runtime::sleep_forever_async, err_str};

use crate::{error::EventManagerError, worker::EventManagerConfig};

// -------------
// | Constants |
// -------------

/// The Unix socket URL scheme
const UNIX_SCHEME: &str = "unix";

/// The error message for when the event export address is not a Unix socket
const ERR_NON_UNIX_EVENT_EXPORT_ADDRESS: &str =
    "Only Unix socket event export addresses are currently supported";

// ---------------------
// | Convenience Types |
// ---------------------

/// A framed sink over a Unix socket
type FramedUnixSink = FramedWrite<UnixStream, LengthDelimitedCodec>;

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
    event_export_addr: Option<Url>,
    /// The chain for which the relayer is configured
    chain: Chain,
    /// The channel on which the coordinator may cancel event manager execution
    cancel_channel: CancelChannel,
}

impl EventManagerExecutor {
    /// Constructs a new event manager executor
    pub fn new(config: EventManagerConfig) -> Self {
        let EventManagerConfig {
            event_queue,
            event_export_url: event_export_addr,
            chain,
            cancel_channel,
        } = config;

        Self { event_queue, event_export_addr, chain, cancel_channel }
    }

    /// Constructs the export sink for the event manager.
    ///
    /// Currently, only Unix socket export addresses are supported.
    pub async fn construct_export_sink(
        &mut self,
    ) -> Result<Option<FramedUnixSink>, EventManagerError> {
        if self.event_export_addr.is_none() {
            return Ok(None);
        }

        let unix_path = extract_unix_socket_path(&self.event_export_addr.take().unwrap())?;

        let socket = UnixStream::connect(Path::new(&unix_path))
            .await
            .map_err(err_str!(EventManagerError::SocketConnection))?;

        let framed_socket = FramedWrite::new(socket, LengthDelimitedCodec::new());

        Ok(Some(framed_socket))
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

                    if let Err(e) = self.handle_relayer_event(event, sink).await {
                        metrics::counter!(NUM_EVENT_EXPORT_FAILURES_METRIC).increment(1);
                        error!("Failed to handle relayer event: {e}");
                    }
                },

                _ = self.cancel_channel.changed() => {
                    info!("EventManager received cancel signal, shutting down...");
                    return Err(EventManagerError::Cancelled("received cancel signal".to_string()));
                }
            }
        }
    }

    /// Handles a relayer event by exporting it to the configured sink
    async fn handle_relayer_event(
        &self,
        event_type: RelayerEventType,
        sink: &mut FramedUnixSink,
    ) -> Result<(), EventManagerError> {
        let event = RelayerEvent::new(self.chain, event_type);
        let event_bytes =
            serde_json::to_vec(&event).map_err(err_str!(EventManagerError::Serialize))?;

        sink.send(event_bytes.into()).await.map_err(err_str!(EventManagerError::SocketWrite))?;
        Ok(())
    }
}

/// Extracts a Unix socket path from the event export URL
pub fn extract_unix_socket_path(event_export_url: &Url) -> Result<String, EventManagerError> {
    match event_export_url.scheme() {
        UNIX_SCHEME => Ok(event_export_url.path().to_string()),
        _ => Err(EventManagerError::InvalidEventExportAddr(
            ERR_NON_UNIX_EVENT_EXPORT_ADDRESS.to_string(),
        )),
    }
}
