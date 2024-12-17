//! Bootloader process; manages the node's startup
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

use funds_manager_api::{
    auth::{compute_hmac, X_SIGNATURE_HEADER},
    gas::{RegisterGasWalletRequest, RegisterGasWalletResponse, REGISTER_GAS_WALLET_ROUTE},
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use std::{collections::HashMap, fmt::Debug, path::Path, str::FromStr};

use aws_config::Region;
use aws_sdk_s3::{error::SdkError, Client as S3Client};
use base64::prelude::*;
use config::parsing::parse_config_from_file;
use libp2p::{identity::Keypair, PeerId};
use tokio::{fs, io::AsyncWriteExt, process::Command};
use toml::Value;
use tracing::{error, info, warn};
use util::{
    raw_err_str,
    telemetry::{setup_system_logger, LevelFilter},
};

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
/// The symmetric key used to authenticate admin API requests (optional)
const ENV_ADMIN_KEY: &str = "ADMIN_API_KEY";
/// The funds manager api URL
const ENV_FUNDS_MANAGER_URL: &str = "FUNDS_MANAGER_URL";
/// The funds manager api key
const ENV_FUNDS_MANAGER_KEY: &str = "FUNDS_MANAGER_KEY";
/// The SQS queue URL
const ENV_SQS_QUEUE_URL: &str = "SQS_QUEUE_URL";

// --- Constants --- //

/// The path at which the relayer expects its config
const CONFIG_PATH: &str = "./config.toml";
/// The http port key name in the relayer config
const CONFIG_HTTP_PORT: &str = "http-port";
/// The websocket port key name in the relayer config
const CONFIG_WS_PORT: &str = "websocket-port";
/// The P2P port key name in the relayer config
const CONFIG_P2P_PORT: &str = "p2p-port";
/// The public IP key name in the relayer config
const CONFIG_PUBLIC_IP: &str = "public-ip";
/// The admin API key name in the relayer config
const CONFIG_ADMIN_KEY: &str = "admin-api-key";
/// The fee whitelist key name in the relayer config
const CONFIG_FEE_WHITELIST: &str = "relayer-fee-whitelist";
/// The p2p key name in the relayer config
const CONFIG_P2P_KEY: &str = "p2p-key";
/// The gas wallet in the relayer config
const CONFIG_GAS_WALLET: &str = "arbitrum-pkeys";

/// The name of the file in the s3 bucket
const WHITELIST_FILE_NAME: &str = "fee-whitelist.json";
/// The path at which the relayer expects the whitelist
const WHITELIST_PATH: &str = "/whitelist.json";

/// The default AWS region to build an s3 client
const DEFAULT_AWS_REGION: &str = "us-east-2";

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
    let whitelist = fetch_fee_whitelist(&s3_client).await?;
    fetch_config(&s3_client).await?;
    modify_config(whitelist).await?;
    download_snapshot(&s3_client).await?;

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

/// Fetch the relayer's config from s3
async fn fetch_config(s3: &S3Client) -> Result<(), String> {
    // Read in the fetch info from environment variables
    let bucket = read_env_var::<String>(ENV_CONFIG_BUCKET)?;
    let file = read_env_var::<String>(ENV_CONFIG_FILE)?;
    download_s3_file(&bucket, &file, CONFIG_PATH, s3).await
}

/// Modify the config using environment variables set at runtime
async fn modify_config(whitelist_path: Option<String>) -> Result<(), String> {
    // Read the config file
    let config_content = fs::read_to_string(CONFIG_PATH)
        .await
        .map_err(raw_err_str!("Failed to read config file: {}"))?;
    let mut config: HashMap<String, Value> =
        toml::from_str(&config_content).map_err(raw_err_str!("Failed to parse config: {}"))?;

    // Setup the peer id and register a gas wallet under this peer id
    let peer_id = set_p2p_key(&mut config);
    setup_gas_wallet(peer_id, &mut config).await?;

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

    if is_env_var_set(ENV_ADMIN_KEY) {
        let admin_key = Value::String(read_env_var(ENV_ADMIN_KEY)?);
        config.insert(CONFIG_ADMIN_KEY.to_string(), admin_key);
    }

    if let Some(path) = whitelist_path {
        let val = Value::String(path);
        config.insert(CONFIG_FEE_WHITELIST.to_string(), val);
    }

    // Write the modified config back to the original file
    let new_config_content =
        toml::to_string(&config).map_err(raw_err_str!("Failed to serialize config: {}"))?;
    fs::write(CONFIG_PATH, new_config_content)
        .await
        .map_err(raw_err_str!("Failed to write config file: {}"))
}

/// Fetch the fee whitelist file from s3
///
/// Returns the path at which the whitelist was downloaded, or None if it
/// doesn't exist
async fn fetch_fee_whitelist(s3: &S3Client) -> Result<Option<String>, String> {
    let bucket = read_env_var::<String>(ENV_CONFIG_BUCKET)?;

    // Check if a whitelist file exists
    match s3.head_object().bucket(bucket.clone()).key(WHITELIST_FILE_NAME).send().await {
        Ok(_) => {},
        Err(SdkError::ServiceError(e)) if e.err().is_not_found() => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };

    download_s3_file(&bucket, WHITELIST_FILE_NAME, WHITELIST_PATH, s3).await?;
    Ok(Some(WHITELIST_PATH.to_string()))
}

/// Download the most recent snapshot
async fn download_snapshot(s3_client: &S3Client) -> Result<(), String> {
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

// --- Helpers --- //

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

/// Set the p2p key in the relayer config and return the associated peer id
fn set_p2p_key(config: &mut HashMap<String, Value>) -> PeerId {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    let key_bytes = keypair.to_protobuf_encoding().unwrap();
    let encoded = BASE64_STANDARD.encode(key_bytes);
    config.insert(CONFIG_P2P_KEY.to_string(), Value::String(encoded));

    peer_id
}

/// Build an s3 client
async fn build_s3_client() -> S3Client {
    let region = Region::new(DEFAULT_AWS_REGION);
    let config = aws_config::from_env().region(region).load().await;
    aws_sdk_s3::Client::new(&config)
}

/// Download an s3 file to the given location
async fn download_s3_file(
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

/// Setup the relayer's gas wallet using the funds manager api
async fn setup_gas_wallet(
    peer_id: PeerId,
    config: &mut HashMap<String, Value>,
) -> Result<(), String> {
    info!("registering gas wallet for relayer...");
    let url = match read_env_var::<String>(ENV_FUNDS_MANAGER_URL) {
        Ok(url) => url,
        Err(_) => {
            warn!("funds manager url not set, skipping gas wallet registration...");
            return Ok(());
        },
    };

    let key = read_funds_manager_key()?;

    // Prepare the request
    let client = Client::new();
    let path = format!("/custody/gas-wallets/{REGISTER_GAS_WALLET_ROUTE}");
    let method = "POST";
    let body = RegisterGasWalletRequest { peer_id: peer_id.to_string() };
    let body_json = serde_json::to_vec(&body).unwrap();

    // Prepare headers
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Compute HMAC
    let hmac = compute_hmac(&key, method, &path, &headers, &body_json);
    let hmac_value =
        HeaderValue::from_str(&hex::encode(hmac)).expect("Failed to create header value");
    headers.insert(X_SIGNATURE_HEADER, hmac_value);

    // Send request
    let url = format!("{}{}", url, path);
    let response = client
        .post(&url)
        .headers(headers)
        .body(body_json)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("Request failed with status: {}", response.status()));
    }

    let resp = response
        .json::<RegisterGasWalletResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let key = Value::String(resp.key);
    config.insert(CONFIG_GAS_WALLET.to_string(), Value::Array(vec![key]));

    Ok(())
}

/// Read in the funds manager HMAC key from environment variables
fn read_funds_manager_key() -> Result<[u8; 32], String> {
    let key_str = read_env_var::<String>(ENV_FUNDS_MANAGER_KEY)?;
    let key_str = key_str.trim_start_matches("0x");

    let decoded = hex::decode(key_str).expect("Invalid HMAC key");
    if decoded.len() != 32 {
        panic!("HMAC key must be 32 bytes long");
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&decoded);
    Ok(array)
}
