//! Keychain helpers for the wallet

use alloy::{
    primitives::keccak256,
    signers::{Signature, SignerSync, local::PrivateKeySigner},
};
use circuit_types::keychain::{
    PublicIdentificationKey, PublicKeyChain, PublicSigningKey, SecretIdentificationKey,
    SecretSigningKey,
};
use constants::Scalar;
use derivative::Derivative;
use k256::ecdsa::SigningKey as K256SigningKey;
use serde::{Deserialize, Serialize};
use util::raw_err_str;

use crate::types::hmac::HmacKey;

use super::Wallet;

/// Represents the private keys a relayer has access to for a given wallet
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Eq)]
pub struct PrivateKeyChain {
    /// Optionally the relayer holds sk_root, in which case the relayer has
    /// heightened permissions than the standard case
    ///
    /// We call such a relayer a "super relayer"
    pub sk_root: Option<SecretSigningKey>,
    /// The match private key, authorizes the relayer to match orders for the
    /// wallet
    pub sk_match: SecretIdentificationKey,
    /// The symmetric HMAC key the user has registered with the relayer for API
    /// authentication
    pub symmetric_key: HmacKey,
}

impl PrivateKeyChain {
    /// Create a new private key chain from a match key and a root key
    pub fn new(
        sk_match: SecretIdentificationKey,
        sk_root: Option<SecretSigningKey>,
        symmetric_key: HmacKey,
    ) -> Self {
        Self { sk_match, sk_root, symmetric_key }
    }

    /// Create a new private key chain without the root key
    pub fn new_without_root(sk_match: SecretIdentificationKey, symmetric_key: HmacKey) -> Self {
        Self { sk_match, sk_root: None, symmetric_key }
    }
}

/// Represents the public and private keys given to the relayer managing a
/// wallet
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChain {
    /// The public keys in the wallet
    pub public_keys: PublicKeyChain,
    /// The secret keys in the wallet
    pub secret_keys: PrivateKeyChain,
}

impl KeyChain {
    /// Increment the keychain nonce
    pub fn increment_nonce(&mut self) {
        self.public_keys.nonce += Scalar::one();
    }

    /// Get the public root key
    pub fn pk_root(&self) -> PublicSigningKey {
        self.public_keys.pk_root.clone()
    }

    /// Set the public root key
    pub fn set_pk_root(&mut self, pk_root: PublicSigningKey) {
        self.public_keys.pk_root = pk_root;
    }

    /// Get the public match key
    pub fn pk_match(&self) -> PublicIdentificationKey {
        self.public_keys.pk_match
    }

    /// Get the secret root key
    pub fn sk_root(&self) -> Option<SecretSigningKey> {
        self.secret_keys.sk_root.clone()
    }

    /// Get the secret match key
    pub fn sk_match(&self) -> SecretIdentificationKey {
        self.secret_keys.sk_match
    }

    /// Get the symmetric key
    pub fn symmetric_key(&self) -> HmacKey {
        self.secret_keys.symmetric_key
    }
}

/// Error message emitted when the wallet does not have an `sk_root` value
const ERR_NO_SK_ROOT: &str = "wallet does not have an `sk_root` value";

impl Wallet {
    /// Sign the given bytes with the wallet's root signing key
    pub fn sign_bytes(&self, bytes: &[u8]) -> Result<Signature, String> {
        // Fetch the `sk_root` key
        let root_key = self.key_chain.secret_keys.sk_root.as_ref().ok_or(ERR_NO_SK_ROOT)?;
        let k256_key = K256SigningKey::try_from(root_key)?;
        let key = PrivateKeySigner::from(k256_key);

        // Sign the payload
        let digest = keccak256(bytes);
        let sig =
            key.sign_hash_sync(&digest).map_err(raw_err_str!("failed to sign commitment: {}"))?;

        Ok(sig)
    }

    /// Sign a wallet transition commitment with the wallet's keychain
    pub fn sign_commitment(&self, commitment: Scalar) -> Result<Signature, String> {
        // Hash the message and sign it as is done in the contract:
        //  https://github.com/renegade-fi/renegade-contracts/blob/main/contracts-common/src/custom_serde.rs#L82-L87
        // The `to_bytes_be` method is used to match the contract's serialization, with
        // appropriate padding
        let comm_bytes = commitment.to_bytes_be();
        self.sign_bytes(&comm_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::types::{tasks::verify_wallet_update_signature, wallet_mocks::mock_empty_wallet};

    /// Check the signature of a commitment against the verification logic in
    /// the update task constructor
    #[test]
    fn test_commitment_signature() {
        let wallet = mock_empty_wallet();
        let key = wallet.key_chain.public_keys.pk_root.clone();
        let comm = wallet.get_wallet_share_commitment();

        // Check the signature
        let sig = wallet.sign_commitment(comm).unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        verify_wallet_update_signature(&wallet, &key, &sig_bytes).unwrap();
    }
}
