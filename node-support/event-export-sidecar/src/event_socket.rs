//! A managed Unix listener that removes the socket file when dropped

use std::{fs, io, path::Path};

use aws_config::Region;
use aws_sdk_sqs::Client as SqsClient;
use event_manager::manager::extract_unix_socket_path;
use eyre::{eyre, Error};
use job_types::event_manager::RelayerEvent;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};
use url::Url;

// -------------
// | Constants |
// -------------

/// The maximum message size to read from the event export socket
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

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
    sqs_client: SqsClient,

    /// The URL of the SQS queue
    queue_url: String,
}

impl EventSocket {
    /// Creates a new event socket from the given URL
    pub async fn new(url: &Url, queue_url: String, region: String) -> Result<Self, Error> {
        let path = extract_unix_socket_path(url)?;
        let socket = Self::establish_socket_connection(&path).await?;

        let config = aws_config::from_env().region(Region::new(region)).load().await;
        let sqs_client = SqsClient::new(&config);

        Ok(Self { socket, path, sqs_client, queue_url })
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
                    if let Err(e) = self.handle_relayer_event(msg.to_vec()).await {
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
    async fn handle_relayer_event(&self, msg: Vec<u8>) -> Result<(), Error> {
        let event: RelayerEvent = serde_json::from_slice(&msg)?;
        let event_id = event.event_id();
        let wallet_id = event.wallet_id();

        let msg = String::from_utf8(msg)?;
        self.sqs_client
            .send_message()
            .queue_url(&self.queue_url)
            .message_deduplication_id(event_id)
            .message_group_id(wallet_id)
            .message_body(msg)
            .send()
            .await?;

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
