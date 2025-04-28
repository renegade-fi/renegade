//! Helpers for deriving wallet keychain types

use std::borrow::Borrow;

use alloy::{
    primitives::keccak256,
    signers::{local::PrivateKeySigner, SignerSync},
};
use circuit_types::keychain::{PublicKeyChain, SecretIdentificationKey};
use constants::Scalar;
use k256::ecdsa::SigningKey;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;
use util::raw_err_str;

use crate::types::hmac::HmacKey;

use super::{
    keychain::{KeyChain, PrivateKeyChain},
    WalletIdentifier,
};

/// The message used to derive the blinder stream seed
const BLINDER_STREAM_SEED_MESSAGE: &[u8] = b"blinder seed";
/// The messages used to derive the share stream seed
const SHARE_STREAM_SEED_MESSAGE: &[u8] = b"share seed";
/// The message used to derive the wallet's root key
const ROOT_KEY_MESSAGE_PREFIX: &str = "Unlock your Renegade Wallet on chain ID:";
/// The message used to derive the wallet's match key
const MATCH_KEY_MESSAGE: &[u8] = b"match key";
/// The message used to derive the wallet's symmetric key
const SYMMETRIC_KEY_MESSAGE: &[u8] = b"symmetric key";
/// The message used to derive the wallet's ID
const WALLET_ID_MESSAGE: &[u8] = b"wallet id";

/// The number of bytes from a keccak hash
const KECCAK_HASH_BYTES: usize = 32;
/// The number of bytes we extend into to get a scalar
const EXTENDED_BYTES: usize = 64;
/// The number of bytes in a wallet ID
const WALLET_ID_BYTES: usize = 16;

lazy_static! {
    /// The secp256k1 scalar field modulus as a BigUint
    ///
    /// See https://en.bitcoin.it/wiki/Secp256k1 for more information
    static ref SECP256K1_SCALAR_MODULUS: BigUint = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    ).unwrap();
}

/// A helper to derive a wallet keychain from a given Ethereum keypair
///
/// This does not necessarily match the implementation used in the clients to
/// generate their wallets
pub fn derive_wallet_keychain(
    eth_key: &PrivateKeySigner,
    chain_id: u64,
) -> Result<KeyChain, String> {
    // Generate the root key
    let sk_root_key = derive_signing_key(&get_root_key_msg(chain_id), eth_key)?;
    let sk_root = sk_root_key.borrow().into();
    let pk_root = sk_root_key.verifying_key().into();

    // Generate the match key, this time using the root key to derive it
    let sk_root_wallet = PrivateKeySigner::from(sk_root_key);
    let sk_match_key = derive_scalar(MATCH_KEY_MESSAGE, &sk_root_wallet)?;
    let sk_match = SecretIdentificationKey::from(sk_match_key);
    let pk_match = sk_match.get_public_key();

    // Generate the symmetric key
    let symmetric_key = derive_symmetric_key(&sk_root_wallet)?;

    Ok(KeyChain {
        public_keys: PublicKeyChain::new(pk_root, pk_match),
        secret_keys: PrivateKeyChain { sk_root: Some(sk_root), sk_match, symmetric_key },
    })
}

/// Construct the blinder seed for the wallet
pub fn derive_blinder_seed(root_key: &PrivateKeySigner) -> Result<Scalar, String> {
    // Sign the blinder seed message and convert to a scalar
    derive_scalar(BLINDER_STREAM_SEED_MESSAGE, root_key)
}

/// Construct the share seed for the wallet
pub fn derive_share_seed(root_key: &PrivateKeySigner) -> Result<Scalar, String> {
    // Sign the share seed message and convert to a scalar
    derive_scalar(SHARE_STREAM_SEED_MESSAGE, root_key)
}

/// Construct a wallet ID from the given Ethereum keypair
///
/// This is done to ensure deterministic wallet recovery
pub fn derive_wallet_id(root_key: &PrivateKeySigner) -> Result<WalletIdentifier, String> {
    let bytes = get_extended_sig_bytes(WALLET_ID_MESSAGE, root_key)?;
    WalletIdentifier::from_slice(&bytes[..WALLET_ID_BYTES])
        .map_err(raw_err_str!("failed to derive wallet ID from key: {}"))
}

// -----------
// | Helpers |
// -----------

/// Get the root key message for the given chain ID
fn get_root_key_msg(chain_id: u64) -> Vec<u8> {
    format!("{} {}", ROOT_KEY_MESSAGE_PREFIX, chain_id).as_bytes().to_vec()
}

/// Get a `Scalar` from a signature on a message
fn derive_scalar(msg: &[u8], key: &PrivateKeySigner) -> Result<Scalar, String> {
    let sig_bytes = get_extended_sig_bytes(msg, key)?;
    Ok(Scalar::from_be_bytes_mod_order(&sig_bytes))
}

/// Derive a signing key from a signature on a message
fn derive_signing_key(msg: &[u8], key: &PrivateKeySigner) -> Result<SigningKey, String> {
    let sig_bytes = get_extended_sig_bytes(msg, key)?;

    // We must manually reduce the bytes to the base field as the k256 library
    // expects byte representations to be of a valid base field element directly
    let unreduced_val = BigUint::from_bytes_be(&sig_bytes);
    let reduced_val = unreduced_val % &*SECP256K1_SCALAR_MODULUS;

    let key_bytes = reduced_val.to_bytes_be();
    SigningKey::from_bytes(key_bytes.as_slice().into())
        .map_err(raw_err_str!("failed to derive signing key from signature: {}"))
}

/// Derive a symmetric key from a signing key
fn derive_symmetric_key(key: &PrivateKeySigner) -> Result<HmacKey, String> {
    get_sig_bytes(SYMMETRIC_KEY_MESSAGE, key).map(HmacKey)
}

/// Sign a message, serialize the signature into bytes
fn get_sig_bytes(msg: &[u8], key: &PrivateKeySigner) -> Result<[u8; KECCAK_HASH_BYTES], String> {
    let digest = keccak256(msg);
    let sig = key.sign_hash_sync(&digest).map_err(raw_err_str!("failed to sign message: {}"))?;

    // Take the keccak hash of the signature to disperse its elements
    let bytes: Vec<u8> = sig.into();
    Ok(*keccak256(bytes))
}

/// Sign a message, serialize the signature into bytes, and extend the bytes to
/// support secure reduction into a field
fn get_extended_sig_bytes(
    msg: &[u8],
    key: &PrivateKeySigner,
) -> Result<[u8; EXTENDED_BYTES], String> {
    let sig_bytes = get_sig_bytes(msg, key)?;
    Ok(extend_to_64_bytes(&sig_bytes))
}

/// Extend the given byte array to 64 bytes, double the length of the original
///
/// This is necessary to give a uniform sampling of a field that these bytes are
/// reduced into, the bitlength must be significantly larger than the field's
/// bitlength to avoid sample bias via modular reduction
fn extend_to_64_bytes(bytes: &[u8]) -> [u8; EXTENDED_BYTES] {
    let mut extended = [0; EXTENDED_BYTES];
    let top_bytes = keccak256(bytes);
    extended[..KECCAK_HASH_BYTES].copy_from_slice(bytes);
    extended[KECCAK_HASH_BYTES..].copy_from_slice(&top_bytes.0);
    extended
}

#[cfg(test)]
mod test {
    use alloy::signers::local::PrivateKeySigner;
    use k256::ecdsa::SigningKey;
    use rand::thread_rng;

    use crate::types::wallet::derivation::get_extended_sig_bytes;

    use super::{derive_blinder_seed, derive_share_seed, derive_wallet_keychain};

    /// The dummy chain ID used for testing
    const CHAIN_ID: u64 = 1;

    /// Tests that blinder seed derivation works
    ///
    /// Does not test correctness, simply that the function does not panic
    #[test]
    fn test_get_blinder_seed() {
        let mut rng = thread_rng();
        let key = SigningKey::random(&mut rng);

        derive_blinder_seed(&key.into()).unwrap();
    }

    /// Tests that share seed derivation works
    ///
    /// Does not test correctness, simply that the function does not panic
    #[test]
    fn test_get_share_seed() {
        let mut rng = thread_rng();
        let key = SigningKey::random(&mut rng);

        derive_share_seed(&key.into()).unwrap();
    }

    /// Tests that the wallet keychain derivation works
    ///
    /// Does not test correctness, simply that the function does not panic
    #[test]
    fn test_derive_wallet_keychain() {
        let mut rng = thread_rng();
        let key = SigningKey::random(&mut rng);

        derive_wallet_keychain(&key.into(), CHAIN_ID).unwrap();
    }

    /// Tests that the key derivation is deterministic
    #[test]
    fn test_deterministic_derivation() {
        let mut rng = thread_rng();
        let msg = b"test message";
        let key = SigningKey::random(&mut rng);
        let wallet = PrivateKeySigner::from(key);

        let sig1 = get_extended_sig_bytes(msg, &wallet).unwrap();
        let sig2 = get_extended_sig_bytes(msg, &wallet).unwrap();
        assert_eq!(sig1, sig2);

        let keychain1 = derive_wallet_keychain(&wallet, CHAIN_ID).unwrap();
        let keychain2 = derive_wallet_keychain(&wallet, CHAIN_ID).unwrap();
        assert_eq!(keychain1, keychain2);
    }
}
