//! A sidecar process that re-exports relayer events for historical state
//! persistence

#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]

mod event_socket;
mod hse_client;

use clap::Parser;
use common::types::wallet::keychain::HmacKey;
use config::parsing::parse_config_from_file;
use event_socket::EventSocket;
use eyre::Error;
use hse_client::HseClient;
use tracing::{info, warn};

// -------
// | CLI |
// -------

/// The event export sidecar CLI
#[derive(Debug, Parser)]
struct Cli {
    /// The path to the relayer's config
    #[clap(long)]
    config_path: String,
    /// The historical state engine URL
    #[clap(long)]
    hse_url: String,
    /// The historical state engine auth key, in base64 format
    #[clap(long)]
    hse_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Parse CLI & config
    let cli = Cli::parse();
    let relayer_config =
        parse_config_from_file(&cli.config_path).expect("could not parse relayer config");
    relayer_config.configure_telemetry().expect("failed to configure telemetry");

    if relayer_config.event_export_url.is_none() {
        warn!("Event export disabled, not creating event sidecar");
        return Ok(());
    }

    // Construct HSE client
    let hse_key = HmacKey::from_base64_string(&cli.hse_key).expect("invalid hse key");
    let hse_client = HseClient::new(cli.hse_url, hse_key);

    let event_socket =
        EventSocket::new(&relayer_config.event_export_url.unwrap(), hse_client).await?;

    info!("Event export sidecar connected to socket, awaiting events...");

    event_socket.listen_for_events().await
}
