//! Helpers for downloading and modifying the relayer config

use std::collections::HashMap;

use aws_sdk_s3::Client as S3Client;
use base64::{prelude::BASE64_STANDARD, Engine};
use libp2p::{identity::Keypair, PeerId};
use tokio::fs;
use toml::Value;
use util::raw_err_str;

use crate::{download_s3_file, is_env_var_set, read_env_var, setup_gas_wallet};

// --- Env Vars --- //

/// The bucket in which the relayer config files are stored
pub(crate) const ENV_CONFIG_BUCKET: &str = "CONFIG_BUCKET";
/// The path in the config bucket
pub(crate) const ENV_CONFIG_FILE: &str = "CONFIG_FILE";
/// The path at which the relayer expects its config
pub(crate) const CONFIG_PATH: &str = "./config.toml";
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
/// The SQS queue URL
pub(crate) const ENV_SQS_QUEUE_URL: &str = "SQS_QUEUE_URL";

// --- Constants --- //

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
/// The p2p key name in the relayer config
const CONFIG_P2P_KEY: &str = "p2p-key";

/// A type alias for the parsed config
///
/// Mapping from key to toml value
pub(crate) type ConfigContents = HashMap<String, Value>;

// ---------------------
// | Config Operations |
// ---------------------

/// Fetch the relayer's config from s3
pub(crate) async fn fetch_config(s3: &S3Client) -> Result<(), String> {
    // Read in the fetch info from environment variables
    let bucket = read_env_var::<String>(ENV_CONFIG_BUCKET)?;
    let file = read_env_var::<String>(ENV_CONFIG_FILE)?;
    download_s3_file(&bucket, &file, CONFIG_PATH, s3).await
}

/// Modify the config using environment variables set at runtime
///
/// Returns the modified config's contents
pub(crate) async fn modify_config() -> Result<ConfigContents, String> {
    // Read the config file
    let config_content = fs::read_to_string(CONFIG_PATH)
        .await
        .map_err(raw_err_str!("Failed to read config file: {}"))?;
    let mut config: ConfigContents =
        toml::from_str(&config_content).map_err(raw_err_str!("Failed to parse config: {}"))?;

    // Setup the peer id and register a gas wallet under this peer id
    let peer_id = set_p2p_key(&mut config)?;
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

    // Write the modified config back to the original file
    let new_config_content =
        toml::to_string(&config).map_err(raw_err_str!("Failed to serialize config: {}"))?;
    fs::write(CONFIG_PATH, new_config_content)
        .await
        .map_err(raw_err_str!("Failed to write config file: {}"))?;

    Ok(config)
}

// -----------
// | Helpers |
// -----------

/// Get the p2p key from the relayer config
fn get_p2p_key(config: &HashMap<String, Value>) -> Result<Option<PeerId>, String> {
    config
        .get(CONFIG_P2P_KEY)
        .map(|val| {
            let key_base64 = val.as_str().ok_or("P2P key is not a string".to_string())?;
            let key_bytes = BASE64_STANDARD
                .decode(key_base64)
                .map_err(raw_err_str!("Failed to decode p2p key from base64: {}"))?;

            let keypair = Keypair::from_protobuf_encoding(&key_bytes)
                .map_err(raw_err_str!("Failed to decode p2p key from protobuf encoding: {}"))?;

            Ok(keypair.public().to_peer_id())
        })
        .transpose()
}

/// Set the p2p key in the relayer config and return the associated peer id
fn set_p2p_key(config: &mut HashMap<String, Value>) -> Result<PeerId, String> {
    if let Some(peer_id) = get_p2p_key(config)? {
        return Ok(peer_id);
    }

    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    let key_bytes =
        keypair.to_protobuf_encoding().map_err(raw_err_str!("Failed to encode p2p key: {}"))?;
    let encoded = BASE64_STANDARD.encode(key_bytes);
    config.insert(CONFIG_P2P_KEY.to_string(), Value::String(encoded));

    Ok(peer_id)
}
