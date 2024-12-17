//! A managed Unix listener that removes the socket file when dropped

use std::{fs, io, path::Path};

use common::types::wallet::keychain::HmacKey;
use event_manager::manager::extract_unix_socket_path;
use eyre::{eyre, Error};
use job_types::event_manager::RelayerEvent;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};
use url::Url;

use crate::{hse_client::HistoricalStateClient, Destination};

// -------------
// | Constants |
// -------------

/// The maximum message size to read from the event export socket
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

// ----------------
// | Destination |
// ----------------

/// The destination to export events to
enum ConfiguredDestination {
    /// The historical state engine
    Hse(HistoricalStateClient),
    /// An AWS SQS queue
    Sqs {
        /// The region in which the SQS queue is located
        region: String,

        /// The name of the SQS queue to send events to
        queue_name: String,
    },
}

// ----------------
// | Event Socket |
// ----------------

/// A managed Unix socket that listens for events on a given path
/// and submits them to the historical state engine.
///
/// The socket file is removed when the socket is dropped.
pub struct EventSocket {
    /// The underlying Unix socket
    socket: UnixStream,

    /// The path to the Unix socket
    path: String,

    /// The destination to export events to
    destination: ConfiguredDestination,
}

impl EventSocket {
    /// Creates a new event socket from the given URL
    pub async fn new(url: &Url, destination: Destination) -> Result<Self, Error> {
        let path = extract_unix_socket_path(url)?;
        let socket = Self::establish_socket_connection(&path).await?;
        let destination = Self::configure_destination(destination)?;
        Ok(Self { socket, path, destination })
    }

    /// Configures the destination for the event socket
    fn configure_destination(destination: Destination) -> Result<ConfiguredDestination, Error> {
        match destination {
            Destination::Hse { hse_url, hse_key } => {
                // Construct HSE client
                let hse_key = HmacKey::from_base64_string(&hse_key)
                    .map_err(|e| eyre!("invalid HSE key: {e}"))?;

                let hse_client = HistoricalStateClient::new(hse_url, hse_key);

                Ok(ConfiguredDestination::Hse(hse_client))
            },
            Destination::Sqs { region, queue_name } => {
                Ok(ConfiguredDestination::Sqs { region, queue_name })
            },
        }
    }

    /// Sets up a Unix socket listening on the given path
    /// and awaits a single connection on it
    async fn establish_socket_connection(path: &str) -> Result<UnixStream, Error> {
        let listener = UnixListener::bind(Path::new(path))?;

        // We only expect one connection, so we can just block on it
        info!("Waiting for event export socket connection...");
        match listener.accept().await {
            Ok((socket, _)) => Ok(socket),
            Err(e) => Err(eyre!("error accepting Unix socket connection: {e}")),
        }
    }

    /// Listens for events on the socket and submits them to the historical
    /// state engine
    pub async fn listen_for_events(&self) -> Result<(), Error> {
        loop {
            // Wait for the socket to be readable
            self.socket.readable().await?;

            let mut buf = [0; MAX_MESSAGE_SIZE];

            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            match self.socket.try_read(&mut buf) {
                Ok(0) => {
                    warn!("Event export socket closed");
                    return Ok(());
                },
                Ok(n) => {
                    let msg = &buf[..n];
                    if let Err(e) = self.handle_relayer_event(msg).await {
                        // Events that fail to be submitted are effectively dropped here.
                        // We can consider retry logic or a local dead-letter queue, but
                        // for now we keep things simple.
                        error!("Error handling relayer event: {e}");
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                },
                Err(e) => {
                    return Err(e.into());
                },
            }
        }
    }

    /// Handles an event received from the event export socket
    async fn handle_relayer_event(&self, msg: &[u8]) -> Result<(), Error> {
        let event = serde_json::from_slice::<RelayerEvent>(msg)?;

        match &self.destination {
            ConfiguredDestination::Hse(hse_client) => {
                hse_client.submit_event(&event).await?;
            },
            ConfiguredDestination::Sqs { .. } => {
                // TODO: Implement SQS destination
                warn!("SQS destination not implemented");
            },
        }

        Ok(())
    }
}

impl Drop for EventSocket {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path) {
            warn!("Failed to remove Unix socket file: {}", e);
        }
    }
}
