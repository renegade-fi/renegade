//! A managed Unix listener that removes the socket file when dropped

use std::{fs, path::Path};

use aws_config::Region;
use aws_sdk_sqs::Client as SqsClient;
use event_manager::manager::extract_unix_socket_path;
use eyre::{eyre, Error};
use job_types::event_manager::RelayerEvent;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};
use tracing::{error, info, warn};
use url::Url;

// ---------------------
// | Convenience Types |
// ---------------------

/// A framed stream over a Unix socket
type FramedUnixStream = FramedRead<UnixStream, LengthDelimitedCodec>;

// -------------
// | Constants |
// -------------

/// The metric name for the number of events failed to be exported by the
/// sidecar
const NUM_SIDECAR_EXPORT_FAILURES_METRIC: &str = "num_event_sidecar_export_failures";

// ----------------
// | Event Socket |
// ----------------

/// A managed Unix socket that listens for events on a given path
/// and submits them to the historical state engine.
///
/// The socket file is removed when the socket is dropped.
pub struct EventSocket {
    /// The underlying Unix socket
    socket: FramedUnixStream,

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
    async fn establish_socket_connection(path: &str) -> Result<FramedUnixStream, Error> {
        let listener = UnixListener::bind(Path::new(path))?;

        // We only expect one connection, so we can just block on it
        info!("Waiting for event export socket connection...");
        match listener.accept().await {
            Ok((socket, _)) => {
                let framed_socket = FramedRead::new(socket, LengthDelimitedCodec::new());
                Ok(framed_socket)
            },
            Err(e) => Err(eyre!("error accepting Unix socket connection: {e}")),
        }
    }

    /// Listens for events on the socket and submits them to the historical
    /// state engine
    pub async fn listen_for_events(&mut self) -> Result<(), Error> {
        while let Some(msg) = self.socket.try_next().await? {
            if let Err(e) = self.handle_relayer_event(msg.to_vec()).await {
                // Events that fail to be submitted are effectively dropped here.
                // We can consider retry logic or a local dead-letter queue, but
                // for now we keep things simple.
                metrics::counter!(NUM_SIDECAR_EXPORT_FAILURES_METRIC).increment(1);
                error!("Error handling relayer event: {e}");
            }
        }

        warn!("Event export socket closed");
        Ok(())
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
