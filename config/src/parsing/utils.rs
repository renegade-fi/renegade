//! Parsing utils

use circuit_types::elgamal::DecryptionKey;
use common::types::hmac::HmacKey;
use ed25519_dalek::{Keypair as DalekKeypair, PublicKey, SecretKey};
use rand::thread_rng;
use rand_core::OsRng;
use util::hex::jubjub_from_hex_string;

use crate::{Cli, RelayerFeeKey};

/// Parse the cluster's symmetric and asymmetric keys from the CLI
pub(crate) fn parse_cluster_keys(cli: &Cli) -> Result<(HmacKey, DalekKeypair), String> {
    // Parse the cluster keypair from CLI args
    // dalek library expects a packed byte array of [PRIVATE_KEY||PUBLIC_KEY]
    let keypair = if let Some(key_str) = cli.cluster_private_key.clone() {
        let pkey_bytes: Vec<u8> = base64::decode(key_str.clone()).unwrap();

        let private_key = SecretKey::from_bytes(&pkey_bytes).unwrap();
        let public_key = PublicKey::from(&private_key);
        DalekKeypair { secret: private_key, public: public_key }
    } else {
        let mut rng = OsRng {};
        DalekKeypair::generate(&mut rng)
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

/// Parse the relayer's decryption key from a string
pub(crate) fn parse_fee_key(
    encryption_key: Option<String>,
    decryption_key: Option<String>,
) -> Result<RelayerFeeKey, String> {
    if let Some(k) = encryption_key {
        let key = jubjub_from_hex_string(&k)?;
        Ok(RelayerFeeKey::new_public(key))
    } else if let Some(k) = decryption_key {
        let key = DecryptionKey::from_hex_str(&k)?;
        Ok(RelayerFeeKey::new_secret(key))
    } else {
        #[cfg(not(feature = "silent"))]
        {
            // Must print here as logger is not yet setup
            use colored::*;
            println!("{}\n", "WARN: No fee decryption key provided, generating one".yellow());
        }

        let mut rng = thread_rng();
        let key = DecryptionKey::random(&mut rng);
        Ok(RelayerFeeKey::new_secret(key))
    }
}
