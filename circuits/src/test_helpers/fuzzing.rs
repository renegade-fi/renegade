//! Fuzzing helpers for generating random test data

use std::cmp;

use alloy_primitives::Address;
use circuit_types::{
    AMOUNT_BITS, Amount,
    csprng::PoseidonCSPRNG,
    elgamal::{DecryptionKey, EncryptionKey},
    fixed_point::FixedPoint,
    intent::Intent,
    settlement_obligation::SettlementObligation,
    state_wrapper::StateWrapper,
    traits::{BaseType, CircuitBaseType, SecretShareBaseType},
    v2::deposit::Deposit,
    withdrawal::Withdrawal,
};
use constants::Scalar;
use itertools::Itertools;
use rand::{Rng, distributions::uniform::SampleRange, thread_rng};
use renegade_crypto::fields::scalar_to_u128;

// -------------------
// | Primitive Types |
// -------------------

/// Generate a random scalar
pub fn random_scalar() -> Scalar {
    let mut rng = thread_rng();
    Scalar::random(&mut rng)
}

/// Create a random sequence of field elements
pub fn random_scalars_vec(n: usize) -> Vec<Scalar> {
    let mut rng = thread_rng();
    (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
}

/// Create a random sequence of field elements as an array
pub fn random_scalars_array<const N: usize>() -> [Scalar; N] {
    random_scalars_vec(N).try_into().unwrap()
}

/// Generate a random amount valid in a wallet
///
/// Leave buffer for additions and subtractions
pub fn random_amount() -> Amount {
    let mut rng = thread_rng();
    let amt = (0..max_amount()).sample_single(&mut rng);

    amt / 10
}

/// Get the maximum amount allowed
pub fn max_amount() -> Amount {
    (1u128 << AMOUNT_BITS) - 1u128
}

/// Generate a random address
pub fn random_address() -> Address {
    let mut rng = thread_rng();
    let mut address_bytes = [0u8; 20];
    rng.fill(&mut address_bytes);
    Address::from(address_bytes)
}

/// Generate a random price
pub fn random_price() -> FixedPoint {
    let min_price = 1.0e-12;
    let max_price = 1.0e12;
    let price_f64 = thread_rng().gen_range(min_price..max_price);

    FixedPoint::from_f64_round_down(price_f64)
}

// ---------------
// | State Types |
// ---------------

/// Create a random deposit
pub fn random_deposit() -> Deposit {
    Deposit { from: random_address(), token: random_address(), amount: random_amount() }
}

/// Create a random withdrawal
pub fn random_withdrawal() -> Withdrawal {
    Withdrawal { to: random_address(), token: random_address(), amount: random_amount() }
}

/// Create a random intent
pub fn random_intent() -> Intent {
    Intent {
        in_token: random_address(),
        out_token: random_address(),
        owner: random_address(),
        min_price: random_price(),
        amount_in: random_amount(),
    }
}

/// Create a random ElGamal encryption key
pub fn random_elgamal_encryption_key() -> EncryptionKey {
    let (enc_key, _) = random_elgamal_keypair();
    enc_key
}

/// Create a random ElGamal keypair
pub fn random_elgamal_keypair() -> (EncryptionKey, DecryptionKey) {
    let mut rng = thread_rng();
    let dec_key = DecryptionKey::random(&mut rng);
    let enc_key = dec_key.public_key();
    (enc_key, dec_key)
}

/// Create a settlement obligation for an intent
pub fn create_settlement_obligation(intent: &Intent) -> SettlementObligation {
    // Use a "virtual" balance that fully capitalizes the intent
    create_settlement_obligation_with_balance(intent, intent.amount_in)
}

/// Create a settlement obligation for an intent and balance amount
pub fn create_settlement_obligation_with_balance(
    intent: &Intent,
    balance_amount: Amount,
) -> SettlementObligation {
    let mut rng = thread_rng();

    // Clamp the obligation's `amount_in` to avoid price overflows
    let mut max_amount_in = 2u128.pow((AMOUNT_BITS / 2) as u32);
    let amount_bound = cmp::min(intent.amount_in, balance_amount);
    max_amount_in = cmp::min(amount_bound, max_amount_in);

    // Sample a random amount
    let amount_in = rng.gen_range(0..=max_amount_in);
    let min_amount_out = compute_min_amount_out(intent, amount_in);
    let amount_out = rng.gen_range(min_amount_out..=max_amount());

    SettlementObligation {
        input_token: intent.in_token,
        output_token: intent.out_token,
        amount_in,
        amount_out,
    }
}

/// Compute the minimum amount out for a given intent and amount in
pub fn compute_min_amount_out(intent: &Intent, amount_in: Amount) -> Amount {
    let min_amount_out = intent.min_price * Scalar::from(amount_in);
    scalar_to_u128(&min_amount_out.floor())
}

/// Create a state wrapper and initialize the share state
pub fn create_state_wrapper<V>(state: V) -> StateWrapper<V>
where
    V: SecretShareBaseType + CircuitBaseType,
    V::ShareType: CircuitBaseType,
{
    let share_seed = random_scalar();
    let recovery_seed = random_scalar();
    StateWrapper::new(state, share_seed, recovery_seed)
}

/// Create a state wrapper for a given state element
pub fn create_random_state_wrapper<V>(state: V) -> StateWrapper<V>
where
    V: SecretShareBaseType + CircuitBaseType,
    V::ShareType: CircuitBaseType,
{
    let mut rng = thread_rng();
    let (_, public_share) = create_random_shares::<V>(&state);
    let mut recovery_stream = random_csprng();
    let mut share_stream = random_csprng();
    recovery_stream.index = rng.r#gen();
    share_stream.index = rng.r#gen();

    StateWrapper { recovery_stream, share_stream, inner: state, public_share }
}

/// Build a random CSPRNG
pub fn random_csprng() -> PoseidonCSPRNG {
    let mut rng = thread_rng();
    let seed = Scalar::random(&mut rng);
    PoseidonCSPRNG::new(seed)
}

/// Create a random sharing of the given type
///
/// Returns a tuple of the private and public shares
pub fn create_random_shares<V: SecretShareBaseType>(v: &V) -> (V::ShareType, V::ShareType) {
    let values = v.to_scalars();
    let private_shares = random_scalars_vec(values.len());
    let public_shares = values.iter().zip(private_shares.iter()).map(|(v, s)| v - s).collect_vec();

    // Deserialize
    let private = V::ShareType::from_scalars(&mut private_shares.into_iter());
    let public = V::ShareType::from_scalars(&mut public_shares.into_iter());
    (private, public)
}
