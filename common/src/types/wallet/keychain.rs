//! Keychain helpers for the wallet

use constants::Scalar;
use ethers::{signers::Wallet as EthersWallet, types::Signature, utils::keccak256};
use k256::ecdsa::SigningKey;

use super::Wallet;

/// Error message emitted when the wallet does not have an `sk_root` value
const ERR_NO_SK_ROOT: &str = "wallet does not have an `sk_root` value";

impl Wallet {
    /// Sign a wallet transition commitment with the wallet's keychain
    pub fn sign_commitment(&self, commitment: Scalar) -> Result<Signature, String> {
        // Fetch the `sk_root` key
        let root_key = self.key_chain.secret_keys.sk_root.as_ref().ok_or(ERR_NO_SK_ROOT)?;
        let key = SigningKey::try_from(root_key)?;
        let wallet = EthersWallet::from(key);

        let comm_bytes = commitment.to_biguint().to_bytes_be();
        let digest = keccak256(comm_bytes);

        // Sign the commitment
        wallet.sign_hash(digest.into()).map_err(|e| e.to_string())
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
