//! Helpers for deriving wallet keychain types

use alloy::{
    primitives::{B256, keccak256},
    signers::{SignerSync, local::PrivateKeySigner},
};
use ark_ff::PrimeField;
use circuit_types::schnorr::SchnorrPrivateKey;
use constants::{EmbeddedScalarField, Scalar};
use darkpool_types::csprng::PoseidonCSPRNG;
use k256::ecdsa::SigningKey;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;
use util::raw_err_str;

use types_core::{AccountId, HmacKey};

use super::keychain::{KeyChain, PrivateKeyChain};

/// The message used to derive the wallet's root key
const ROOT_KEY_MESSAGE_PREFIX: &str = "Unlock your Renegade Wallet on chain ID:";
/// The message used to derive the wallet's master view seed
const MASTER_VIEW_SEED_MESSAGE: &[u8] = b"master view seed";
/// The message which is hashed alongside a master view seed to generate the
/// share seed CSPRNG seed
const MASTER_SHARE_SEED_CSPRNG_MESSAGE: &[u8] = b"share-seed-csprng";
/// The message which is hashed alongside a master view seed to generate the
/// recovery seed CSPRNG seed
const MASTER_RECOVERY_SEED_CSPRNG_MESSAGE: &[u8] = b"recovery-seed-csprng";
/// The message prefix used to derive the Schnorr key
const SCHNORR_KEY_MESSAGE_PREFIX: &[u8] = b"schnorr key";
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
/// The number of bytes in a signing key
const SIGNING_KEY_BYTES: usize = 32;

lazy_static! {
    /// The secp256k1 scalar field modulus as a BigUint
    ///
    /// See https://en.bitcoin.it/wiki/Secp256k1 for more information
    static ref SECP256K1_SCALAR_MODULUS: BigUint = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    ).unwrap();
}

/// Construct a wallet ID from the given Ethereum keypair
///
/// This is done to ensure deterministic account recovery
pub fn derive_account_id(root_key: &PrivateKeySigner) -> Result<AccountId, String> {
    let bytes = get_extended_sig_bytes(WALLET_ID_MESSAGE, root_key)?;
    AccountId::from_slice(&bytes[..WALLET_ID_BYTES])
        .map_err(raw_err_str!("failed to derive account ID from key: {}"))
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
    let root_key = derive_signing_key(&get_root_key_msg(chain_id), eth_key)?;
    let root_signer = PrivateKeySigner::from(root_key);

    // Generate the master view seed and symmetric key from the root key
    let master_view_seed = derive_scalar(MASTER_VIEW_SEED_MESSAGE, &root_signer)?;
    let symmetric_key = derive_symmetric_key(&root_signer)?;

    // Derive the Schnorr key pair
    let schnorr_private_key = derive_schnorr_key(&root_signer, chain_id)?;
    let schnorr_public_key = schnorr_private_key.public_key();

    // Build the keychain
    let private_keychain = PrivateKeyChain::new(symmetric_key, master_view_seed);
    Ok(KeyChain::new(private_keychain, schnorr_public_key))
}

/// Derive a master share stream seed from a master view seed
pub fn derive_master_share_stream_seed(master_view_seed: &Scalar) -> PoseidonCSPRNG {
    let mut msg = master_view_seed.to_bytes_be();
    msg.extend_from_slice(MASTER_SHARE_SEED_CSPRNG_MESSAGE);
    let seed = hash_to_scalar(&msg);
    PoseidonCSPRNG::new(seed)
}

/// Derive a recovery stream seed from a master view seed
pub fn derive_recovery_stream_seed(master_view_seed: &Scalar) -> PoseidonCSPRNG {
    let mut msg = master_view_seed.to_bytes_be();
    msg.extend_from_slice(MASTER_RECOVERY_SEED_CSPRNG_MESSAGE);
    let seed = hash_to_scalar(&msg);
    PoseidonCSPRNG::new(seed)
}
/// Derive a Schnorr private key from a signing key and chain ID
fn derive_schnorr_key(key: &PrivateKeySigner, chain_id: u64) -> Result<SchnorrPrivateKey, String> {
    let sig_bytes = get_extended_sig_bytes(&schnorr_key_message(chain_id), key)?;
    let inner = EmbeddedScalarField::from_be_bytes_mod_order(&sig_bytes);
    Ok(SchnorrPrivateKey { inner })
}

// -----------
// | Helpers |
// -----------

/// Get the root key message for the given chain ID
fn get_root_key_msg(chain_id: u64) -> Vec<u8> {
    format!("{} {}", ROOT_KEY_MESSAGE_PREFIX, chain_id).as_bytes().to_vec()
}

/// Generate the message to sign for Schnorr key derivation
fn schnorr_key_message(chain_id: u64) -> Vec<u8> {
    let mut message = Vec::from(SCHNORR_KEY_MESSAGE_PREFIX);
    message.extend_from_slice(&chain_id.to_be_bytes());
    message
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
    let mut padded_key_bytes = vec![0_u8; SIGNING_KEY_BYTES];
    let pad_size = SIGNING_KEY_BYTES - key_bytes.len();
    padded_key_bytes[pad_size..].copy_from_slice(&key_bytes);
    SigningKey::from_bytes(padded_key_bytes.as_slice().into())
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

/// Hash a message to a scalar. We do this by hashing the message, extending the
/// hash to 64 bytes, then performing modular reduction of the result into a
/// scalar.
///
/// We do this to ensure a uniform sampling of the scalar field.
pub fn hash_to_scalar(msg: &[u8]) -> Scalar {
    // Hash the message
    let msg_hash = keccak256(msg);

    // Hash the hash again
    let recursive_hash = keccak256(msg_hash);

    // Concatenate the hashes
    let mut extended_hash = [0u8; B256::len_bytes() * 2];
    extended_hash[..B256::len_bytes()].copy_from_slice(msg_hash.as_slice());
    extended_hash[B256::len_bytes()..].copy_from_slice(recursive_hash.as_slice());

    // Perform modular reduction
    Scalar::from_be_bytes_mod_order(&extended_hash)
}

#[cfg(all(test, feature = "mocks"))]
mod test {
    use alloy::signers::local::PrivateKeySigner;
    use k256::ecdsa::SigningKey;
    use rand::thread_rng;

    use super::{derive_wallet_keychain, get_extended_sig_bytes};

    /// The dummy chain ID used for testing
    const CHAIN_ID: u64 = 1;

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
