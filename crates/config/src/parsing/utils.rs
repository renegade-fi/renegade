//! Parsing utils

use std::{collections::HashMap, str::FromStr};

use types_core::HmacKey;
use types_gossip::ClusterAsymmetricKeypair;

use crate::Cli;

/// Parse the cluster's symmetric and asymmetric keys from the CLI
pub(crate) fn parse_cluster_keys(cli: &Cli) -> Result<(HmacKey, ClusterAsymmetricKeypair), String> {
    // Parse the cluster keypair from CLI args
    // dalek library expects a packed byte array of [PRIVATE_KEY||PUBLIC_KEY]
    let keypair = if let Some(key_str) = cli.cluster_private_key.clone() {
        ClusterAsymmetricKeypair::from_base64(&key_str)
            .map_err(|_| "Invalid cluster keypair".to_string())?
    } else {
        ClusterAsymmetricKeypair::random()
    };

    // Parse the symmetric key from its string or generate
    let symmetric_key: HmacKey = if let Some(key_str) = cli.cluster_symmetric_key.clone() {
        parse_symmetric_key(key_str)?
    } else {
        HmacKey::random()
    };

    Ok((symmetric_key, keypair))
}

/// Parse a symmetric key from a base64 string
pub(crate) fn parse_symmetric_key(key_str: String) -> Result<HmacKey, String> {
    base64::decode(key_str)
        .map_err(|e| e.to_string())?
        .try_into()
        .map(HmacKey)
        .map_err(|_| "Invalid symmetric key".to_string())
}

/// Parse a string keyed map into a hashmap
///
/// This will be "key1=value1,key2=value2,..."
pub(crate) fn parse_cli_map<T: FromStr>(s: &str) -> Result<HashMap<String, T>, String> {
    // Trim whitespace and any trailing comma
    let s = s.trim().trim_end_matches(',');
    if s.is_empty() {
        return Ok(HashMap::new());
    }

    // Split the string into pairs
    let mut map = HashMap::new();
    for pair in s.split(',') {
        // Split the pair into key and value
        let (key, value) = pair.split_once('=').ok_or("Invalid map format")?;
        // Parse the value
        let parsed_value = T::from_str(value).map_err(|_| "Invalid map value")?;
        map.insert(key.to_string(), parsed_value);
    }

    Ok(map)
}
