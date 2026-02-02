//! A sidecar process that proxies requests to the darkpool indexer and sends
//! messages to AWS SQS

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]

mod server;
mod sqs;

use aws_config::Region;
use aws_sdk_sqs::Client as SqsClient;
use clap::Parser;
use config::parsing::config_file::parse_config_from_file;
use eyre::Result;
use server::run_server;
use tracing::info;
use url::Url;

// -------
// | CLI |
// -------

/// The indexer message sidecar CLI
#[derive(Debug, Parser)]
struct Cli {
    /// The path to the relayer's config
    #[clap(long)]
    config_path: String,

    /// The URL of the indexer to proxy requests to
    #[clap(long, env = "INDEXER_URL")]
    indexer_url: String,

    /// The region in which the SQS queue is located
    #[clap(short, long)]
    region: String,

    /// The URL of the SQS queue to send messages to
    #[clap(short, long)]
    queue_url: String,

    /// The port to listen on
    #[clap(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI & config
    let cli = Cli::parse();
    let relayer_config =
        parse_config_from_file(&cli.config_path).expect("could not parse relayer config");

    relayer_config.configure_telemetry().expect("failed to configure telemetry");

    // Parse the indexer URL
    let indexer_url: Url = cli.indexer_url.parse().expect("invalid indexer URL");

    // Build the SQS client
    let config = aws_config::from_env().region(Region::new(cli.region)).load().await;
    let sqs_client = SqsClient::new(&config);

    info!("Starting indexer message sidecar on port {}", cli.port);

    // Run the server
    run_server(cli.port, indexer_url, sqs_client, cli.queue_url).await
}
