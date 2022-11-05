//! Groups helpers involving the scalar field that the MPC network is defined over

use num_bigint::BigUint;

/// Returns the prime group modulus for the scalar field that Dalek Ristretto
/// arithmetic is defined over.
pub fn get_ristretto_group_modulus() -> BigUint {
    let modulus: BigUint = BigUint::from(1u64) << 252;
    let delta_digits = String::from("27742317777372353535851937790883648493")
        .chars()
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect::<Vec<_>>();

    let delta = BigUint::from_radix_be(&delta_digits, 10 /* radix */).unwrap();
    modulus + delta
}
