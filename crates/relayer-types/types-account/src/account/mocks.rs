//! Mock types for wallet testing

use circuits_core::test_helpers::{random_address, random_amount, random_price};
use constants::{MERKLE_HEIGHT, Scalar};
use darkpool_types::intent::Intent;
use num_bigint::BigUint;
use rand::thread_rng;

use types_core::AccountId;

use crate::{Account, MerkleAuthenticationPath};

/// Create a mock empty account
pub fn mock_empty_account() -> Account {
    Account::new_empty_account(AccountId::new_v4())
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

/// Create a mock Merkle path for a wallet
pub fn mock_merkle_path() -> MerkleAuthenticationPath {
    let mut rng = thread_rng();
    MerkleAuthenticationPath::new(
        [Scalar::random(&mut rng); MERKLE_HEIGHT],
        BigUint::from(0u8),
        Scalar::random(&mut rng),
    )
}
