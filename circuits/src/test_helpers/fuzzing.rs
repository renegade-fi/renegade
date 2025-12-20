//! Fuzzing helpers for generating random test data

use std::cmp;

use alloy_primitives::Address;
use circuit_types::{
    AMOUNT_BITS, Amount,
    balance::{Balance, PostMatchBalanceShare},
    bounded_match_result::BoundedMatchResult,
    csprng::PoseidonCSPRNG,
    deposit::Deposit,
    elgamal::{DecryptionKey, EncryptionKey},
    fixed_point::FixedPoint,
    intent::Intent,
    max_amount,
    schnorr::{SchnorrPrivateKey, SchnorrPublicKey},
    settlement_obligation::SettlementObligation,
    state_wrapper::StateWrapper,
    traits::{BaseType, CircuitBaseType, SecretShareBaseType},
    withdrawal::Withdrawal,
};
use constants::{MAX_RELAYER_FEE_RATE, Scalar};
use itertools::Itertools;
use rand::{Rng, distributions::uniform::SampleRange, thread_rng};
use renegade_crypto::fields::scalar_to_u128;

/// The bounded maximum amount to prevent `Amount` overflow in tests
pub const BOUNDED_MAX_AMT: Amount = 2u128.pow((AMOUNT_BITS / 2) as u32);

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

/// Generate a random fee
pub fn random_fee() -> FixedPoint {
    let mut rng = thread_rng();
    let fee_f64 = rng.gen_range(0.0..=MAX_RELAYER_FEE_RATE);
    FixedPoint::from_f64_round_down(fee_f64)
}

/// Generate a random block deadline
pub fn random_block_deadline() -> u64 {
    let mut rng = thread_rng();
    rng.gen_range(0..=u64::MAX)
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
    random_bounded_intent(max_amount())
}

/// Create a random intent at half the bitlength of the maximum amount
///
/// We do this so that a match on the intent does not overflow the bitlength of
/// the receive balance amount
pub fn random_small_intent() -> Intent {
    random_bounded_intent(BOUNDED_MAX_AMT)
}

/// Create a random bounded intent
pub fn random_bounded_intent(max_amount_in: Amount) -> Intent {
    let mut rng = thread_rng();
    let amount_in = rng.gen_range(0..=max_amount_in);
    Intent {
        in_token: random_address(),
        out_token: random_address(),
        owner: random_address(),
        min_price: random_price(),
        amount_in,
    }
}

/// Create a balance that matches the given intent
///
/// The balance will have the same owner and mint as the intent's in_token,
/// with random values for other fields.
pub fn create_matching_balance_for_intent(intent: &Intent) -> Balance {
    Balance {
        mint: intent.in_token,
        owner: intent.owner,
        relayer_fee_recipient: random_address(),
        authority: random_schnorr_public_key(),
        relayer_fee_balance: random_amount(),
        protocol_fee_balance: random_amount(),
        amount: random_amount(),
    }
}

/// Create a random balance with a small initial amount
pub fn random_small_balance() -> Balance {
    random_bounded_balance(BOUNDED_MAX_AMT)
}

/// Create a random balance
pub fn random_balance() -> Balance {
    random_bounded_balance(max_amount())
}

/// Create a random balance with a bounded initial amount
pub fn random_bounded_balance(max_amount: Amount) -> Balance {
    let mut rng = thread_rng();
    let amount = rng.gen_range(0..=max_amount);
    Balance {
        mint: random_address(),
        owner: random_address(),
        relayer_fee_recipient: random_address(),
        authority: random_schnorr_public_key(),
        relayer_fee_balance: random_amount(),
        protocol_fee_balance: random_amount(),
        amount,
    }
}

/// Create a random zero'd balance
pub fn random_zeroed_balance() -> Balance {
    Balance {
        mint: random_address(),
        owner: random_address(),
        relayer_fee_recipient: random_address(),
        authority: random_schnorr_public_key(),
        relayer_fee_balance: 0,
        protocol_fee_balance: 0,
        amount: 0,
    }
}

/// Create a random post-match balance share
pub fn random_post_match_balance_share() -> PostMatchBalanceShare {
    PostMatchBalanceShare {
        amount: random_scalar(),
        relayer_fee_balance: random_scalar(),
        protocol_fee_balance: random_scalar(),
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

/// Create a random Schnorr keypair
pub fn random_schnorr_keypair() -> (SchnorrPrivateKey, SchnorrPublicKey) {
    let private_key = SchnorrPrivateKey::random();
    let public_key = private_key.public_key();
    (private_key, public_key)
}

/// Create a random Schnorr public key
pub fn random_schnorr_public_key() -> SchnorrPublicKey {
    let (_, public_key) = random_schnorr_keypair();
    public_key
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
    let amount_bound = cmp::min(intent.amount_in, balance_amount);
    let max_amount_in = cmp::min(amount_bound, BOUNDED_MAX_AMT);

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

/// Create a bounded match result for an intent
pub fn create_bounded_match_result(intent: &Intent) -> BoundedMatchResult {
    create_bounded_match_result_with_balance(intent, intent.amount_in)
}

/// Create a bounded match result for an intent and balance amount
pub fn create_bounded_match_result_with_balance(
    intent: &Intent,
    balance_amount: Amount,
) -> BoundedMatchResult {
    let mut rng = thread_rng();

    // Clamp the obligation's `amount_in` to avoid price overflows
    let amount_bound = cmp::min(intent.amount_in, balance_amount);
    let mut max_amount_in = cmp::min(amount_bound, BOUNDED_MAX_AMT);

    // Choose a random upper bound for the match result
    max_amount_in = rng.gen_range(0..=max_amount_in);
    let min_amount_in = rng.gen_range(0..=max_amount_in);

    BoundedMatchResult {
        internal_party_input_token: intent.in_token,
        internal_party_output_token: intent.out_token,
        min_internal_party_amount_in: min_amount_in,
        max_internal_party_amount_in: max_amount_in,
        price: intent.min_price,
        block_deadline: random_block_deadline(),
    }
}

/// Compute the minimum amount out for a given intent and amount in
pub fn compute_min_amount_out(intent: &Intent, amount_in: Amount) -> Amount {
    let min_amount_out = intent.min_price * Scalar::from(amount_in);
    scalar_to_u128(&min_amount_out.floor())
}

/// Compute the maximum amount out for a given bounded match result
///
/// This computes the maximum output amount based on the price and maximum
/// input amount: `floor(price * max_internal_party_amount_in)`
pub fn compute_max_amount_out(bounded_match_result: &BoundedMatchResult) -> Amount {
    let max_amount_out = bounded_match_result.price
        * Scalar::from(bounded_match_result.max_internal_party_amount_in);
    scalar_to_u128(&max_amount_out.floor())
}

/// Compute the implied price for a given amount out and in
pub fn compute_implied_price(amount_out: Amount, amount_in: Amount) -> FixedPoint {
    let price = (amount_out as f64) / (amount_in as f64);
    FixedPoint::from_f64_round_down(price)
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
