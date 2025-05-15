//! Bootloader process; manages the node's startup
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use config::{fetch_config, modify_config, CONFIG_PATH, ENV_SQS_QUEUE_URL};
use gas_wallet::setup_gas_wallet;
use helpers::{
    build_s3_client, download_s3_file, in_bootstrap_mode, is_env_var_set, read_env_var,
    DEFAULT_AWS_REGION,
};
use snapshot::{download_snapshot, ENV_SNAP_BUCKET};
use tokio::process::Command;
use tracing::error;
use util::telemetry::{setup_system_logger, LevelFilter};

mod config;
mod gas_wallet;
mod helpers;
mod snapshot;

/// The location of the snapshot sidecar binary
const SNAPSHOT_SIDECAR_BIN: &str = "/bin/snapshot-sidecar";
/// The location of the event export sidecar binary
const EVENT_EXPORT_SIDECAR_BIN: &str = "/bin/event-export-sidecar";
/// The location of the relayer binary
const RELAYER_BIN: &str = "/bin/renegade-relayer";

// --- Main --- //

#[tokio::main]
async fn main() -> Result<(), String> {
    setup_system_logger(LevelFilter::INFO);

    // Build an s3 client
    let s3_client = build_s3_client().await;

    // Fetch the config, modify it, and download the most recent snapshot
    fetch_config(&s3_client).await?;
    let cfg = modify_config().await?;
    download_snapshot(&s3_client, &cfg).await?;

    // Start the snapshot sidecar, event export sidecar, and the relayer
    let bucket = read_env_var::<String>(ENV_SNAP_BUCKET)?;
    let mut snapshot_sidecar = Command::new(SNAPSHOT_SIDECAR_BIN)
        .args(["--config-path", CONFIG_PATH])
        .args(["--bucket", &bucket])
        .spawn()
        .expect("Failed to start snapshot sidecar process");

    let sqs_queue_url = read_env_var::<String>(ENV_SQS_QUEUE_URL)?;
    let mut event_export_sidecar = Command::new(EVENT_EXPORT_SIDECAR_BIN)
        .args(["--config-path", CONFIG_PATH])
        .args(["--queue-url", &sqs_queue_url])
        .args(["--region", DEFAULT_AWS_REGION])
        .spawn()
        .expect("Failed to start event export sidecar process");

    let mut relayer = Command::new(RELAYER_BIN)
        .args(["--config-file", CONFIG_PATH])
        .spawn()
        .expect("Failed to start relayer process");

    let snapshot_sidecar_result = snapshot_sidecar.wait();
    let event_export_sidecar_result = event_export_sidecar.wait();
    let relayer_result = relayer.wait();
    let (snapshot_sidecar_result, event_export_sidecar_result, relayer_result) = tokio::try_join!(
        snapshot_sidecar_result,
        event_export_sidecar_result,
        relayer_result
    )
    .expect(
        "Either snapshot sidecar, event export sidecar, or relayer process encountered an error",
    );

    error!("snapshot sidecar exited with: {:?}", snapshot_sidecar_result);
    error!("event export sidecar exited with: {:?}", event_export_sidecar_result);
    error!("relayer exited with: {:?}", relayer_result);
    Ok(())
}

// --- Helpers --- //
