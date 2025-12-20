//! Helper methods for the integration tests

use circuit_types::Amount;
use eyre::Result;

/// Check whether two values are within a given tolerance of one another
pub fn assert_approx_eq(a: Amount, b: Amount, tolerance: f64) -> Result<()> {
    let a_f64 = a as f64;
    let b_f64 = b as f64;
    let diff = (a_f64 - b_f64).abs();
    let diff_percent = diff / a_f64;

    if diff_percent > tolerance {
        eyre::bail!("expected {a} to be within {}% of {b}", tolerance * 100.);
    }

    Ok(())
}
