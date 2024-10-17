//! Mock types for wallet testing

use std::{
    iter,
    sync::{atomic::AtomicUsize, Arc},
};

use circuit_types::{
    elgamal::DecryptionKey,
    fixed_point::FixedPoint,
    keychain::{PublicKeyChain, PublicSigningKey, SecretIdentificationKey, SecretSigningKey},
    order::OrderSide,
    traits::BaseType,
    SizedWalletShare,
};
use constants::{Scalar, ADDRESS_BYTE_LENGTH, MERKLE_HEIGHT};
use k256::ecdsa::SigningKey as K256SigningKey;
use num_bigint::BigUint;
use rand::{thread_rng, Rng, RngCore};
use uuid::Uuid;

use crate::{keyed_list::KeyedList, types::merkle::MerkleAuthenticationPath};

use super::{
    keychain::{HmacKey, KeyChain, PrivateKeyChain},
    orders::{Order, OrderBuilder},
    Wallet,
};

/// Create a mock empty wallet
pub fn mock_empty_wallet() -> Wallet {
    // Create an initial wallet
    let mut rng = thread_rng();

    // Sample a valid signing key
    let key = K256SigningKey::random(&mut rng);
    let sk_root = Some(SecretSigningKey::from(&key));
    let pk_root = PublicSigningKey::from(key.verifying_key());

    let sk_match = SecretIdentificationKey::from(Scalar::random(&mut rng));
    let pk_match = sk_match.get_public_key();
    let symmetric_key = HmacKey::random();

    let (_, managing_cluster_key) = DecryptionKey::random_pair(&mut rng);

    let mut wallet = Wallet {
        wallet_id: Uuid::new_v4(),
        orders: KeyedList::default(),
        balances: KeyedList::default(),
        key_chain: KeyChain {
            public_keys: PublicKeyChain::new(pk_root, pk_match),
            secret_keys: PrivateKeyChain { sk_root, sk_match, symmetric_key },
        },
        blinder: Scalar::random(&mut rng),
        match_fee: FixedPoint::from_integer(0),
        managing_cluster: managing_cluster_key,
        private_shares: SizedWalletShare::from_scalars(&mut iter::repeat_with(|| {
            Scalar::random(&mut rng)
        })),
        blinded_public_shares: SizedWalletShare::from_scalars(&mut iter::repeat_with(|| {
            Scalar::random(&mut rng)
        })),
        merkle_proof: Some(mock_merkle_path()),
        merkle_staleness: Arc::new(AtomicUsize::default()),
    };

    // Reblind the wallet so that the secret shares a valid sharing of the wallet
    wallet.reblind_wallet();
    wallet
}

/// Create a mock order
pub fn mock_order() -> Order {
    let mut rng = thread_rng();
    OrderBuilder::new()
        .quote_mint(rand_addr_biguint())
        .base_mint(rand_addr_biguint())
        .side(OrderSide::Buy)
        .amount(rng.next_u64().into())
        .worst_case_price(FixedPoint::from_integer(rng.gen()))
        .min_fill_size(rng.gen())
        .build()
        .unwrap()
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

// -----------
// | Helpers |
// -----------

/// Generate a random address as a BigUint
pub fn rand_addr_biguint() -> BigUint {
    let mut rng = thread_rng();
    let mut addr_bytes = [0_u8; ADDRESS_BYTE_LENGTH];
    rng.fill_bytes(&mut addr_bytes);
    BigUint::from_bytes_be(&addr_bytes)
}
