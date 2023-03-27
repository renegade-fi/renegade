//! Groups together long-running async tasks for best discoverability
//!
//! Examples of such tasks are creating a new wallet; which requires the
//! node to prove `VALID NEW WALLET`, submit the wallet on-chain, wait for
//! transaction success, and then prove `VALID COMMITMENTS`

use crypto::{
    elgamal::{encrypt_scalar, ElGamalCiphertext},
    fields::biguint_to_scalar,
};
use itertools::Itertools;
use num_bigint::BigUint;

use crate::SizedWallet;

pub mod create_new_order;
pub mod create_new_wallet;
pub mod driver;

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
