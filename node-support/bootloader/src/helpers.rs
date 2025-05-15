//! Helpers for the bootloader

use std::{fmt::Debug, path::Path, str::FromStr};

use aws_config::Region;
use aws_sdk_s3::Client as S3Client;
use tokio::{fs, io::AsyncWriteExt};
use util::raw_err_str;

use crate::config::ConfigContents;

// --- Environment Variables --- //

/// The bootstrap mode flag in the relayer config
const CONFIG_BOOTSTRAP_MODE: &str = "bootstrap-mode";
/// The default AWS region to build an s3 client
pub(crate) const DEFAULT_AWS_REGION: &str = "us-east-2";

/// Check whether the given environment variable is set
pub(crate) fn is_env_var_set(var_name: &str) -> bool {
    std::env::var(var_name).is_ok()
}

/// Read an environment variable
pub(crate) fn read_env_var<T: FromStr>(var_name: &str) -> Result<T, String>
where
    <T as FromStr>::Err: Debug,
{
    std::env::var(var_name)
        .map_err(raw_err_str!("{var_name} not set: {}"))?
        .parse::<T>()
        .map_err(|e| format!("Failed to read env var {}: {:?}", var_name, e))
}

/// Return whether the relayer is in bootstrap mode
pub(crate) fn in_bootstrap_mode(config: &ConfigContents) -> bool {
    config.get(CONFIG_BOOTSTRAP_MODE).map(|val| val.as_bool().unwrap_or(false)).unwrap_or(false)
}

// --- S3 --- //

/// Build an s3 client
pub(crate) async fn build_s3_client() -> S3Client {
    let region = Region::new(DEFAULT_AWS_REGION);
    let config = aws_config::from_env().region(region).load().await;
    aws_sdk_s3::Client::new(&config)
}

/// Download an s3 file to the given location
pub(crate) async fn download_s3_file(
    bucket: &str,
    key: &str,
    destination: &str,
    s3_client: &S3Client,
) -> Result<(), String> {
    // Get the object from S3
    let resp = s3_client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(raw_err_str!("Failed to get object from S3: {}"))?;
    let body = resp.body.collect().await.map_err(raw_err_str!("Failed to read object body: {}"))?;

    // Create the directory if it doesn't exist
    if let Some(parent) = Path::new(destination).parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(raw_err_str!("Failed to create destination directory: {}"))?;
    }

    // Write the body to the destination file
    let mut file = fs::File::create(destination)
        .await
        .map_err(raw_err_str!("Failed to create destination file: {}"))?;
    file.write_all(&body.into_bytes())
        .await
        .map_err(raw_err_str!("Failed to write to destination file: {}"))?;

    Ok(())
}
