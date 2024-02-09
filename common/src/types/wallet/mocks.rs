//! Mock types for wallet testing

use std::{
    iter,
    sync::{atomic::AtomicUsize, Arc},
};

use circuit_types::{
    fixed_point::FixedPoint,
    keychain::{PublicKeyChain, PublicSigningKey, SecretIdentificationKey, SecretSigningKey},
    order::{Order, OrderSide},
    traits::BaseType,
    SizedWalletShare,
};
use constants::{Scalar, MERKLE_HEIGHT};
use k256::ecdsa::SigningKey as K256SigningKey;
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_biguint;
use uuid::Uuid;

use crate::{keyed_list::KeyedList, types::merkle::MerkleAuthenticationPath};

use super::{KeyChain, PrivateKeyChain, Wallet};

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

    let mut wallet = Wallet {
        wallet_id: Uuid::new_v4(),
        orders: KeyedList::default(),
        balances: KeyedList::default(),
        fees: vec![],
        key_chain: KeyChain {
            public_keys: PublicKeyChain { pk_root, pk_match },
            secret_keys: PrivateKeyChain { sk_root, sk_match },
        },
        blinder: Scalar::random(&mut rng),
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
    let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
    let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));
    let amount = 10u64;
    let worst_case_price = FixedPoint::from_integer(100);
    let timestamp = 0u64;

    Order { quote_mint, base_mint, amount, worst_case_price, timestamp, side: OrderSide::Buy }
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
