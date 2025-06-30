//! Helpers for downloading the latest relayer snapshot

use aws_sdk_s3::Client as S3Client;
use config::parsing::parse_config_from_file;
use tracing::info;
use util::raw_err_str;

use crate::{
    CONFIG_PATH, config::ConfigContents, download_s3_file, in_bootstrap_mode, read_env_var,
};

/// The snapshot bucket environment variable
pub(crate) const ENV_SNAP_BUCKET: &str = "SNAPSHOT_BUCKET";

/// Download the most recent snapshot
pub(crate) async fn download_snapshot(
    s3_client: &S3Client,
    cfg: &ConfigContents,
) -> Result<(), String> {
    if in_bootstrap_mode(cfg) {
        info!("skipping snapshot download in bootstrap mode");
        return Ok(());
    }

    info!("downloading latest snapshot...");
    let bucket = read_env_var::<String>(ENV_SNAP_BUCKET)?;

    // Parse the relayer's config
    let relayer_config =
        parse_config_from_file(CONFIG_PATH).expect("could not parse relayer config");
    let snap_path = format!("cluster-{}", relayer_config.cluster_id);

    // Get the latest snapshot
    let snaps = s3_client
        .list_objects_v2()
        .bucket(&bucket)
        .prefix(&snap_path)
        .send()
        .await
        .map_err(raw_err_str!("Failed to list objects in S3: {}"))?
        .contents
        .unwrap_or_default();
    if snaps.is_empty() {
        info!("no snapshots found in s3");
        return Ok(());
    }

    let latest = snaps.iter().max_by_key(|obj| obj.last_modified.as_ref().unwrap()).unwrap();
    let latest_key = latest.key.as_ref().unwrap();

    // Download the snapshot into the snapshot directory
    let path = format!("{}/snapshot.gz", relayer_config.raft_snapshot_path);
    download_s3_file(&bucket, latest_key, &path, s3_client).await
}
