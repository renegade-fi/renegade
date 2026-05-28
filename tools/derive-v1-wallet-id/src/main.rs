//! derive-v1-wallet-id
//!
//! Reads 32-byte ETH private keys (hex, one per line, optional `0x` prefix
//! and optional trailing label on the same line) on stdin and writes the
//! v1 renegade wallet_id for each. Used by the Task 4 internal-wallet
//! enumeration to compute quoter and custodied-funds wallet IDs from the
//! secrets we hold.
//!
//! Input lines:
//!   <hex_key>             # derives wallet_id at CHAIN_ID
//!   <hex_key> <label>     # same, label echoed in output
//!
//! Output, tab-separated:
//!   <wallet_id_uuid> <eth_address_lowercase> <pk_root_uncompressed_hex> <label?>
//!
//! Env:
//!   CHAIN_ID  default 42161 (Arbitrum One mainnet)

use std::io::{self, BufRead, Write};

use alloy::signers::local::PrivateKeySigner;
use circuit_types::keychain::SecretSigningKey;
use common::types::wallet::derivation::{derive_wallet_id, derive_wallet_keychain};
use eyre::{Result, WrapErr, eyre};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn process_line(line: &str, chain_id: u64) -> Result<(String, String, String, String)> {
    let mut parts = line.split_whitespace();
    let hex_key = parts.next().ok_or_else(|| eyre!("empty line"))?;
    let label = parts.collect::<Vec<_>>().join(" ");

    let key_bytes = hex::decode(hex_key.trim_start_matches("0x"))
        .wrap_err("hex decode")?;
    let signer: PrivateKeySigner = K256SigningKey::from_slice(&key_bytes)
        .wrap_err("k256 signing key from slice")?
        .into();
    let eth_addr = format!("0x{:x}", signer.address());

    // derive_wallet_keychain runs the v1 derivation: signs the chain-id
    // message, reduces into a secp256k1 scalar to get sk_root, then
    // produces the full KeyChain.
    let kc = derive_wallet_keychain(&signer, chain_id)
        .map_err(|e| eyre!("derive_wallet_keychain: {e}"))?;
    let sk_root: SecretSigningKey = kc
        .secret_keys
        .sk_root
        .ok_or_else(|| eyre!("derived KeyChain has no sk_root"))?;

    // Rebuild a PrivateKeySigner around sk_root so we can pass it to
    // derive_wallet_id (signs "wallet id", takes first 16 bytes as UUID).
    let sk_root_k256 = K256SigningKey::try_from(&sk_root)
        .map_err(|e| eyre!("sk_root → K256: {e}"))?;
    let sk_root_signer: PrivateKeySigner = sk_root_k256.clone().into();

    let wallet_id = derive_wallet_id(&sk_root_signer)
        .map_err(|e| eyre!("derive_wallet_id: {e}"))?;

    // pk_root as uncompressed SEC1 (0x04 || x || y), hex.
    let vk = sk_root_k256.verifying_key();
    let pk_hex = hex::encode(vk.to_encoded_point(false /* compress */).as_bytes());

    Ok((wallet_id.to_string(), eth_addr, pk_hex, label))
}

fn main() -> Result<()> {
    let chain_id: u64 = std::env::var("CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42161);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    let mut n_ok = 0u64;
    let mut n_err = 0u64;
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match process_line(trimmed, chain_id) {
            Ok((wid, addr, pk, label)) => {
                if label.is_empty() {
                    writeln!(out, "{wid}\t{addr}\t{pk}")?;
                } else {
                    writeln!(out, "{wid}\t{addr}\t{pk}\t{label}")?;
                }
                n_ok += 1;
            }
            Err(e) => {
                writeln!(err, "ERROR: {trimmed} → {e:#}")?;
                n_err += 1;
            }
        }
    }
    writeln!(err, "done. ok={n_ok} err={n_err} chain_id={chain_id}")?;
    Ok(())
}
