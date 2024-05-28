//! Bootloader process; manages the node's startup
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use std::{collections::HashMap, fmt::Debug, str::FromStr};

use aws_config::Region;
use aws_sdk_s3::Client as S3Client;
use tokio::{fs, fs::File, io::AsyncWriteExt, process::Command};
use toml::Value;
use tracing::error;
use util::raw_err_str;

// --- Env Vars --- //

/// The snapshot bucket environment variable
const ENV_SNAP_BUCKET: &str = "SNAPSHOT_BUCKET";
/// The bucket in which the relayer config files are stored
const ENV_CONFIG_BUCKET: &str = "CONFIG_BUCKET";
/// The path in the config bucket
const ENV_CONFIG_FILE: &str = "CONFIG_FILE";
/// The HTTP port to listen on
const ENV_HTTP_PORT: &str = "HTTP_PORT";
/// The websocket port to listen on
const ENV_WS_PORT: &str = "WEBSOCKET_PORT";
/// The P2P port to listen on
const ENV_P2P_PORT: &str = "P2P_PORT";
/// The public IP of the node (optional)
const ENV_PUBLIC_IP: &str = "PUBLIC_IP";

// --- Constants --- //

/// The path at which the relayer expects its config
const CONFIG_PATH: &str = "/config.toml";
/// The http port key name in the relayer config
const CONFIG_HTTP_PORT: &str = "http-port";
/// The websocket port key name in the relayer config
const CONFIG_WS_PORT: &str = "websocket-port";
/// The P2P port key name in the relayer config
const CONFIG_P2P_PORT: &str = "p2p-port";
/// The public IP key name in the relayer config
const CONFIG_PUBLIC_IP: &str = "public-ip";

/// The default AWS region to build an s3 client
const DEFAULT_AWS_REGION: &str = "us-east-2";

/// The location of the snapshot sidecar binary
const SIDECAR_BIN: &str = "/bin/snapshot-sidecar";
/// The location of the relayer binary
const RELAYER_BIN: &str = "/bin/renegade-relayer";

// --- Main --- //

#[tokio::main]
async fn main() -> Result<(), String> {
    // Build an s3 client
    let s3_client = build_s3_client().await;

    // Fetch the config, modify it, and download the most recent snapshot
    fetch_config(s3_client).await?;
    modify_config().await?;
    download_snapshot().await?;

    // Start both the snapshot sidecar and the relayer
    let bucket = read_env_var::<String>(ENV_SNAP_BUCKET)?;
    let mut sidecar = Command::new(SIDECAR_BIN)
        .args(["--config-path", CONFIG_PATH])
        .args(["--bucket", &bucket])
        .spawn()
        .expect("Failed to start snapshot sidecar process");
    let mut relayer = Command::new(RELAYER_BIN)
        .args(["--config-file", CONFIG_PATH])
        .spawn()
        .expect("Failed to start relayer process");

    let sidecar_result = sidecar.wait();
    let relayer_result = relayer.wait();
    let (sidecar_result, relayer_result) = tokio::try_join!(sidecar_result, relayer_result)
        .expect("Either snapshot sidecar or relayer process encountered an error");

    error!("sidecar exited with: {:?}", sidecar_result);
    error!("relayer exited with: {:?}", relayer_result);
    Ok(())
}

/// Fetch the relayer's config from s3
async fn fetch_config(s3: S3Client) -> Result<(), String> {
    // Read in the fetch info from environment variables
    let bucket = read_env_var::<String>(ENV_CONFIG_BUCKET)?;
    let file = read_env_var::<String>(ENV_CONFIG_FILE)?;

    // Fetch the config
    let resp = s3
        .get_object()
        .bucket(bucket)
        .key(file)
        .send()
        .await
        .map_err(raw_err_str!("Failed to fetch config from s3: {}"))?;

    // Write the body to the config file
    let mut file = File::create(CONFIG_PATH)
        .await
        .map_err(raw_err_str!("Failed to create config file: {}"))?;
    let body = resp.body.collect().await.map_err(raw_err_str!("error streaming config: {}"))?;
    file.write_all(&body.to_vec()).await.map_err(raw_err_str!("error writing config: {}"))
}

/// Modify the config using environment variables set at runtime
async fn modify_config() -> Result<(), String> {
    // Read the config file
    let config_content = fs::read_to_string(CONFIG_PATH)
        .await
        .map_err(raw_err_str!("Failed to read config file: {}"))?;
    let mut config: HashMap<String, Value> =
        toml::from_str(&config_content).map_err(raw_err_str!("Failed to parse config: {}"))?;

    // Add values from the environment variables
    let http_port = Value::String(read_env_var(ENV_HTTP_PORT)?);
    let ws_port = Value::String(read_env_var(ENV_WS_PORT)?);
    let p2p_port = Value::String(read_env_var(ENV_P2P_PORT)?);
    config.insert(CONFIG_HTTP_PORT.to_string(), http_port);
    config.insert(CONFIG_WS_PORT.to_string(), ws_port);
    config.insert(CONFIG_P2P_PORT.to_string(), p2p_port);

    if is_env_var_set(ENV_PUBLIC_IP) {
        let public_ip = Value::String(read_env_var(ENV_PUBLIC_IP)?);
        config.insert(CONFIG_PUBLIC_IP.to_string(), public_ip);
    }

    // Write the modified config back to the original file
    let new_config_content =
        toml::to_string(&config).map_err(raw_err_str!("Failed to serialize config: {}"))?;
    fs::write(CONFIG_PATH, new_config_content)
        .await
        .map_err(raw_err_str!("Failed to write config file: {}"))
}

/// Download the most recent snapshot
async fn download_snapshot() -> Result<(), String> {
    Ok(())
}

// --- Helpers --- //

/// Build an s3 client
async fn build_s3_client() -> S3Client {
    let region = Region::new(DEFAULT_AWS_REGION);
    let config = aws_config::from_env().region(region).load().await;
    aws_sdk_s3::Client::new(&config)
}

/// Check whether the given environment variable is set
fn is_env_var_set(var_name: &str) -> bool {
    std::env::var(var_name).is_ok()
}

/// Read an environment variable
fn read_env_var<T: FromStr>(var_name: &str) -> Result<T, String>
where
    <T as FromStr>::Err: Debug,
{
    std::env::var(var_name)
        .map_err(raw_err_str!("{var_name} not set: {}"))?
        .parse::<T>()
        .map_err(|e| format!("Failed to read env var {}: {:?}", var_name, e))
}
