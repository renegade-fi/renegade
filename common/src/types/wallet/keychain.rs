//! Keychain helpers for the wallet

use constants::Scalar;
use ethers::{
    core::k256::ecdsa::SigningKey as EthersSigningKey,
    types::{Signature, U256},
    utils::keccak256,
};
use util::raw_err_str;

use super::Wallet;

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
        let comm_bytes = commitment.to_biguint().to_bytes_be();
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
