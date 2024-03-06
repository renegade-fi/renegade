//! Helpers for deriving wallet keychain types

use std::borrow::Borrow;

use circuit_types::keychain::{PublicKeyChain, SecretIdentificationKey};
use constants::Scalar;
use ethers::{signers::LocalWallet as EthWallet, utils::keccak256};
use k256::ecdsa::SigningKey;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;
use util::raw_err_str;

use super::{KeyChain, PrivateKeyChain, WalletIdentifier};

/// The message used to derive the blinder stream seed
const BLINDER_STREAM_SEED_MESSAGE: &[u8] = b"blinder_stream_seed||v0";
/// The messages used to derive the share stream seed
const SHARE_STREAM_SEED_MESSAGE: &[u8] = b"share_stream_seed||v0";
/// The message used to derive the wallet's root key
const ROOT_KEY_MESSAGE: &[u8] = b"root_key||v0";
/// The message used to derive the wallet's match key
const MATCH_KEY_MESSAGE: &[u8] = b"match_key||v0";
/// The message used to derive the wallet's ID
const WALLET_ID_MESSAGE: &[u8] = b"wallet_id||v0";

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
pub fn derive_wallet_keychain(eth_key: &EthWallet) -> Result<KeyChain, String> {
    // Generate the match key
    let sk_match_key = derive_scalar(MATCH_KEY_MESSAGE, eth_key)?;
    let sk_match = SecretIdentificationKey::from(sk_match_key);
    let pk_match = sk_match.get_public_key();

    // Generate the root key
    let sk_root_key = derive_signing_key(ROOT_KEY_MESSAGE, eth_key)?;
    let sk_root = sk_root_key.borrow().into();
    let pk_root = sk_root_key.verifying_key().into();

    Ok(KeyChain {
        public_keys: PublicKeyChain { pk_root, pk_match },
        secret_keys: PrivateKeyChain { sk_root: Some(sk_root), sk_match },
    })
}

/// Construct the blinder seed for the wallet
pub fn derive_blinder_seed(key: &EthWallet) -> Result<Scalar, String> {
    // Sign the blinder seed message and convert to a scalar
    derive_scalar(BLINDER_STREAM_SEED_MESSAGE, key)
}

/// Construct the share seed for the wallet
pub fn derive_share_seed(key: &EthWallet) -> Result<Scalar, String> {
    // Sign the share seed message and convert to a scalar
    derive_scalar(SHARE_STREAM_SEED_MESSAGE, key)
}

/// Construct a wallet ID from the given Ethereum keypair
///
/// This is done to ensure deterministic wallet recovery
pub fn derive_wallet_id(key: &EthWallet) -> Result<WalletIdentifier, String> {
    let bytes = get_extended_sig_bytes(WALLET_ID_MESSAGE, key)?;
    WalletIdentifier::from_slice(&bytes[..WALLET_ID_BYTES])
        .map_err(raw_err_str!("failed to derive wallet ID from key: {}"))
}

// -----------
// | Helpers |
// -----------

/// Get a `Scalar` from a signature on a message
fn derive_scalar(msg: &[u8], key: &EthWallet) -> Result<Scalar, String> {
    let sig_bytes = get_extended_sig_bytes(msg, key)?;

    Ok(Scalar::from_be_bytes_mod_order(&sig_bytes))
}

/// Derive a signing key from a signature on a message
fn derive_signing_key(msg: &[u8], key: &EthWallet) -> Result<SigningKey, String> {
    let sig_bytes = get_extended_sig_bytes(msg, key)?;

    // We must manually reduce the bytes to the base field as the k256 library
    // expects byte representations to be of a valid base field element directly
    let unreduced_val = BigUint::from_bytes_be(&sig_bytes);
    let reduced_val = unreduced_val % &*SECP256K1_SCALAR_MODULUS;

    let key_bytes = reduced_val.to_bytes_be();
    SigningKey::from_bytes(key_bytes.as_slice().into())
        .map_err(raw_err_str!("failed to derive signing key from signature: {}"))
}

/// Sign a message, serialize the signature into bytes
fn get_extended_sig_bytes(msg: &[u8], key: &EthWallet) -> Result<[u8; EXTENDED_BYTES], String> {
    let digest = keccak256(msg);
    let wallet = EthWallet::from(key.clone());
    let sig =
        wallet.sign_hash(digest.into()).map_err(raw_err_str!("failed to sign message: {}"))?;

    // Take the keccak hash of the signature to disperse its elements
    let bytes = sig.to_vec();
    let keccak_bytes = keccak256(bytes);
    Ok(extend_to_64_bytes(&keccak_bytes))
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
    extended[KECCAK_HASH_BYTES..].copy_from_slice(&top_bytes);
    extended
}

#[cfg(test)]
mod test {
    use ethers::signers::LocalWallet;
    use k256::ecdsa::SigningKey;
    use rand::thread_rng;

    use crate::types::wallet::keychain::get_extended_sig_bytes;

    use super::{derive_blinder_seed, derive_share_seed, derive_wallet_keychain};

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

        derive_wallet_keychain(&key.into()).unwrap();
    }

    /// Tests that the key derivation is deterministic
    #[test]
    fn test_deterministic_derivation() {
        let mut rng = thread_rng();
        let msg = b"test message";
        let key = SigningKey::random(&mut rng);
        let wallet = LocalWallet::from(key);

        let sig1 = get_extended_sig_bytes(msg, &wallet).unwrap();
        let sig2 = get_extended_sig_bytes(msg, &wallet).unwrap();
        assert_eq!(sig1, sig2);

        let keychain1 = derive_wallet_keychain(&wallet).unwrap();
        let keychain2 = derive_wallet_keychain(&wallet).unwrap();
        assert_eq!(keychain1, keychain2);
    }
}
