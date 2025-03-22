//! Helpers for using wallets on-chain

use alloy::signers::local::PrivateKeySigner;
use ethers::signers::LocalWallet;

/// Convert an alloy private key signer to an ethers wallet
pub fn alloy_signer_to_ethers_wallet(signer: &PrivateKeySigner) -> LocalWallet {
    let secret_key = signer.credential().clone();
    LocalWallet::from(secret_key)
}
