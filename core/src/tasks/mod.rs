//! Groups together long-running async tasks for best discoverability
//!
//! Examples of such tasks are creating a new wallet; which requires the
//! node to prove `VALID NEW WALLET`, submit the wallet on-chain, wait for
//! transaction success, and then prove `VALID COMMITMENTS`

use std::convert::TryInto;

use circuits::types::{
    balance::Balance, fee::Fee, keychain::KeyChain as CircuitKeyChain, note::Note, order::Order,
};
use crypto::{
    elgamal::{decrypt_scalar, encrypt_scalar, ElGamalCiphertext},
    fields::{biguint_to_scalar, scalar_to_biguint},
};
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use num_bigint::BigUint;

use crate::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS};

pub mod create_new_order;
pub mod create_new_wallet;
pub mod driver;
pub mod external_transfer;
pub mod initialize_state;
pub mod lookup_wallet;
pub mod settle_match;

/// The amount to increment the randomness each time a wallet is nullified
pub(self) const RANDOMNESS_INCREMENT: u8 = 2;

// -----------
// | Helpers |
// -----------

/// A helper to encrypt a wallet under a given public view key
pub(self) fn encrypt_wallet(wallet: SizedWallet, pk_view: &BigUint) -> Vec<ElGamalCiphertext> {
    let mut ciphertexts = Vec::new();

    // Encrypt the balances
    wallet.balances.iter().for_each(|balance| {
        ciphertexts.push(encrypt_scalar(biguint_to_scalar(&balance.mint), pk_view));
        ciphertexts.push(encrypt_scalar(balance.amount.into(), pk_view));
    });

    // Encrypt the orders
    wallet.orders.iter().for_each(|order| {
        ciphertexts.push(encrypt_scalar(
            biguint_to_scalar(&order.quote_mint),
            pk_view,
        ));
        ciphertexts.push(encrypt_scalar(biguint_to_scalar(&order.base_mint), pk_view));
        ciphertexts.push(encrypt_scalar(order.side.into(), pk_view));
        ciphertexts.push(encrypt_scalar(order.price.into(), pk_view));
        ciphertexts.push(encrypt_scalar(order.amount.into(), pk_view));
        ciphertexts.push(encrypt_scalar(order.timestamp.into(), pk_view));
    });

    // Encrypt the fees
    wallet.fees.iter().for_each(|fee| {
        ciphertexts.push(encrypt_scalar(biguint_to_scalar(&fee.settle_key), pk_view));
        ciphertexts.push(encrypt_scalar(biguint_to_scalar(&fee.gas_addr), pk_view));
        ciphertexts.push(encrypt_scalar(fee.gas_token_amount.into(), pk_view));
        ciphertexts.push(encrypt_scalar(fee.percentage_fee.into(), pk_view));
    });

    // Encrypt the wallet randomness
    ciphertexts.push(encrypt_scalar(wallet.randomness, pk_view));

    // Remove the randomness used in each encryption, cleaner this way than
    // indexing into the tuple struct in all of the above
    ciphertexts
        .into_iter()
        .map(|(cipher, _)| cipher)
        .collect_vec()
}

/// Helper to decrypt a wallet under a given key
pub(self) fn decrypt_wallet(
    ciphertext: Vec<ElGamalCiphertext>,
    secret_key: &BigUint,
    keys: CircuitKeyChain,
) -> SizedWallet {
    // Decrypt the ciphertext blob
    let mut plaintexts = ciphertext
        .into_iter()
        .map(|cipher| decrypt_scalar(cipher, secret_key))
        .collect_vec();

    // Reverse so that we can pop in the following restructuring process
    plaintexts.reverse();

    // Re-structure into a wallet
    // Re-structure the balances
    let mut balances = Vec::with_capacity(MAX_BALANCES);
    for _ in 0..MAX_BALANCES {
        balances.push(Balance {
            mint: scalar_to_biguint(&plaintexts.pop().unwrap()),
            amount: scalar_to_u64(&plaintexts.pop().unwrap()),
        })
    }

    // Re-structure the orders
    let mut orders = Vec::with_capacity(MAX_ORDERS);
    for _ in 0..MAX_ORDERS {
        orders.push(Order {
            quote_mint: scalar_to_biguint(&plaintexts.pop().unwrap()),
            base_mint: scalar_to_biguint(&plaintexts.pop().unwrap()),
            side: plaintexts.pop().unwrap().into(),
            price: plaintexts.pop().unwrap().into(),
            amount: scalar_to_u64(&plaintexts.pop().unwrap()),
            timestamp: scalar_to_u64(&plaintexts.pop().unwrap()),
        })
    }

    // Re-structure the fees
    let mut fees = Vec::with_capacity(MAX_FEES);
    for _ in 0..MAX_FEES {
        fees.push(Fee {
            settle_key: scalar_to_biguint(&plaintexts.pop().unwrap()),
            gas_addr: scalar_to_biguint(&plaintexts.pop().unwrap()),
            gas_token_amount: scalar_to_u64(&plaintexts.pop().unwrap()),
            percentage_fee: plaintexts.pop().unwrap().into(),
        })
    }

    let randomness = plaintexts.pop().unwrap();

    SizedWallet {
        balances: balances.try_into().unwrap(),
        orders: orders.try_into().unwrap(),
        fees: fees.try_into().unwrap(),
        keys,
        randomness,
    }
}

/// Helper to encrypt a note under a given key
pub(self) fn encrypt_note(note: Note, pk_settle: &BigUint) -> Vec<ElGamalCiphertext> {
    Into::<Vec<Scalar>>::into(note)
        .into_iter()
        .map(|val| encrypt_scalar(val, pk_settle))
        .map(|(cipher, _)| cipher)
        .collect_vec()
}
