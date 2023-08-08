use mpc_stark::algebra::scalar::Scalar;

pub mod arithmetic;
pub mod bits;
pub mod comparators;
pub mod modulo;
pub mod poseidon;

// -----------
// | Helpers |
// -----------

/// Assert two scalars are equal, returning a `String` error if they are not
pub fn assert_scalar_eq(a: &Scalar, b: &Scalar) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("Expected {:?} == {:?}", a, b))
    }
}

/// Assert two batches of scalars are equal, returning a `String` error if they are not
pub fn assert_scalar_batch_eq(a: &[Scalar], b: &[Scalar]) -> Result<(), String> {
    if a.len() != b.len() {
        return Err(format!(
            "Expected batch lengths to be equal: {} != {}",
            a.len(),
            b.len()
        ));
    }

    for (a, b) in a.iter().zip(b.iter()) {
        assert_scalar_eq(a, b)?;
    }

    Ok(())
}
