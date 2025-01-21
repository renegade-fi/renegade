//! Keychain helpers for the wallet

use circuit_types::keychain::{
    PublicIdentificationKey, PublicKeyChain, PublicSigningKey, SecretIdentificationKey,
    SecretSigningKey,
};
use constants::Scalar;
use contracts_common::custom_serde::BytesSerializable;
use derivative::Derivative;
use ethers::{
    core::k256::ecdsa::SigningKey as EthersSigningKey,
    types::{Signature, U256},
    utils::keccak256,
};
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
    /// Sign a wallet transition commitment with the wallet's keychain
    ///
    /// The contracts expect a recoverable signature with the recover ID set to
    /// 0/1; we use ethers `sign_prehash_recoverable` to generate this signature
    pub fn sign_commitment(&self, commitment: Scalar) -> Result<Signature, String> {
        // Fetch the `sk_root` key
        let root_key = self.key_chain.secret_keys.sk_root.as_ref().ok_or(ERR_NO_SK_ROOT)?;
        let key = EthersSigningKey::try_from(root_key)?;

        // Hash the message and sign it
        let comm_bytes = commitment.inner().serialize_to_bytes();
        let digest = keccak256(comm_bytes);
        let (sig, recovery_id) = key
            .sign_prehash_recoverable(&digest)
            .map_err(raw_err_str!("failed to sign commitment: {}"))?;

        Ok(Signature {
            r: U256::from_big_endian(&sig.r().to_bytes()),
            s: U256::from_big_endian(&sig.s().to_bytes()),
            v: recovery_id.to_byte() as u64,
        })
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
        verify_wallet_update_signature(&wallet, &key, &sig.to_vec()).unwrap();
    }
}
