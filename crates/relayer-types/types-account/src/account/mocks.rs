//! Mock types for wallet testing

use circuit_types::schnorr::SchnorrPrivateKey;
use constants::{MERKLE_HEIGHT, Scalar};
use darkpool_types::fuzzing::{random_address, random_amount, random_price};
use darkpool_types::intent::Intent;
use rand::thread_rng;

use types_core::{AccountId, HmacKey};

use crate::{
    Account, MerkleAuthenticationPath,
    keychain::{KeyChain, PrivateKeyChain},
};

/// Create a mock empty account
pub fn mock_empty_account() -> Account {
    let id = AccountId::new_v4();
    let keychain = mock_keychain();
    Account::new_empty_account(id, keychain)
}

/// Create a mock intent
pub fn mock_intent() -> Intent {
    Intent {
        in_token: random_address(),
        out_token: random_address(),
        owner: random_address(),
        min_price: random_price(),
        amount_in: random_amount(),
    }
}

/// Create a mock keychain
pub fn mock_keychain() -> KeyChain {
    let mut rng = thread_rng();
    let hmac_key = HmacKey::random();
    let master_view_seed = Scalar::random(&mut rng);
    let schnorr_public_key = SchnorrPrivateKey::random().public_key();
    let private_keychain = PrivateKeyChain::new(hmac_key, master_view_seed);
    KeyChain::new(private_keychain, schnorr_public_key)
}

/// Create a mock Merkle path for a wallet
pub fn mock_merkle_path() -> MerkleAuthenticationPath {
    let mut rng = thread_rng();
    MerkleAuthenticationPath::new(
        [Scalar::random(&mut rng); MERKLE_HEIGHT],
        0u64,
        Scalar::random(&mut rng),
    )
}
