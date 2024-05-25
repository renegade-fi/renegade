//! A sidecar process that manages snapshots emitted by the relayer

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use std::{
    path::Path,
    sync::mpsc::channel,
    time::{Duration, Instant},
};

use aws_config::Region;
use aws_sdk_s3::{primitives::ByteStream, Client};
use clap::Parser;
use external_api::http::admin::{IsLeaderResponse, IS_LEADER_ROUTE};
use notify::{event::ModifyKind, Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::Client as HttpClient;
use tracing::{error, info};
use util::{
    get_current_time_millis, raw_err_str,
    telemetry::{setup_system_logger, LevelFilter},
};

/// The sidecar CLI
#[derive(Debug, Parser)]
struct Cli {
    /// The path to watch for snapshot files
    #[clap(short, long)]
    path: String,
    /// The name of the s3 bucket to send snapshots to
    #[clap(short, long)]
    bucket: String,
    /// The region to send snapshots to
    #[clap(short, long, default_value = "us-east-2")]
    region: String,
    /// The address of the relayer's HTTP api
    ///
    /// By default assumes the relayer is on the same machine listening on port
    /// 3000
    #[clap(short, long, default_value = "http://localhost:3000")]
    http_addr: String,
    /// The number of seconds in between modify events to trigger a snapshot
    #[clap(short, long, default_value = "5")]
    interval: u64,
}

/// Main
#[tokio::main]
async fn main() {
    // Parse the CLI
    let cli = Cli::parse();
    let path = Path::new(&cli.path);
    setup_system_logger(LevelFilter::INFO);

    let region = Region::new(cli.region.clone());
    let config = aws_config::from_env().region(region).load().await;
    let s3_client = aws_sdk_s3::Client::new(&config);

    // Build a notification channel
    let (tx, rx) = channel();
    let mut watcher =
        RecommendedWatcher::new(tx, Config::default()).expect("Failed to create watcher");
    watcher.watch(path, RecursiveMode::NonRecursive).expect("Failed to watch path");

    // Listen for events
    let debounce_interval = Duration::from_secs(cli.interval);
    let mut last_event = Instant::now() - debounce_interval;
    for event in rx.iter().flatten() {
        if let EventKind::Modify(ModifyKind::Data(..)) = event.kind {
            if Instant::now() - last_event > debounce_interval {
                maybe_record_snapshot(&cli, &s3_client).await;
                last_event = Instant::now();
            }
        }
    }
}

/// Check if the local node is the leader and record the snapshot if so
async fn maybe_record_snapshot(args: &Cli, s3_client: &Client) {
    // Check if the local relayer is the leader first
    match check_leader(&args.http_addr).await {
        Ok(false) => {
            info!("relayer is not leader, skipping");
            return;
        },
        Ok(true) => {},
        Err(e) => {
            error!("Failed to check leader: {e}");
            return;
        },
    };

    // Record the snapshot
    let path = Path::new(&args.path);
    if let Err(e) = handle_new_snapshot(path, &args.bucket, s3_client).await {
        error!("Failed to handle new snapshot: {e}");
    }
}

/// Copy a snapshot to s3
async fn handle_new_snapshot(path: &Path, bucket: &str, s3_client: &Client) -> Result<(), String> {
    let ts = get_current_time_millis();
    let file_name = format!("snapshot-{ts}.zip");
    info!("uploading snapshot: {file_name} to {bucket}");

    // Send the file at `path` to the s3 bucket
    let body = ByteStream::read_from().path(path).build().await.map_err(raw_err_str!("{}"))?;
    let put_object_request = s3_client.put_object().bucket(bucket).key(file_name).body(body);

    put_object_request
        .send()
        .await
        .map_err(raw_err_str!("Failed to upload file to S3: {}"))
        .map(|_| ())
}

/// Check whether the local relayer is a leader
async fn check_leader(api_base: &str) -> Result<bool, String> {
    let client = HttpClient::new();
    let endpoint = format!("{}{}", api_base, IS_LEADER_ROUTE);
    let res =
        client.get(endpoint).send().await.map_err(|e| format!("Failed to send request: {}", e))?;

    res.json::<IsLeaderResponse>()
        .await
        .map(|r| r.leader)
        .map_err(|e| format!("Failed to parse response: {}", e))
}
