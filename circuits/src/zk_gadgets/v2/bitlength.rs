//! Gadgets for validating bit-lengths of state types

use circuit_types::{
    AMOUNT_BITS, FEE_BITS, Fabric, MpcPlonkCircuit, PRICE_BITS, PlonkCircuit,
    fixed_point::FixedPointVar,
};
use mpc_relation::{Variable, errors::CircuitError};

use crate::zk_gadgets::bits::{BitRangeGadget, MultiproverBitRangeGadget};

/// Constrain a value to be a valid `Amount`, i.e. a non-negative `Scalar`
/// representable in at most `AMOUNT_BITS` bits
pub struct AmountGadget;
impl AmountGadget {
    /// Constrain an value to be a valid `Amount`
    pub fn constrain_valid_amount(
        amount: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::constrain_bit_range(amount, AMOUNT_BITS, cs)
    }
}

/// Constrain a value to be a valid `Amount` in a multiprover context
pub struct MultiproverAmountGadget;
impl MultiproverAmountGadget {
    /// Constrain an value to be a valid `Amount`
    pub fn constrain_valid_amount(
        amount: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        MultiproverBitRangeGadget::constrain_bit_range(amount, AMOUNT_BITS, fabric, cs)
    }
}

/// Constrain a fee to be in the range of valid take rates
///
/// This is [0, 2^FEE_BITS-1]
pub struct FeeGadget;
impl FeeGadget {
    /// Constrain a value to be a valid fee
    pub fn constrain_valid_fee(
        fee: FixedPointVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::constrain_bit_range(fee.repr, FEE_BITS, cs)
    }
}

/// Constrain a value to be a valid `FixedPoint` price
pub struct PriceGadget;
impl PriceGadget {
    /// Constrain a value to be a valid `FixedPoint` price
    pub fn constrain_valid_price(
        price: FixedPointVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::constrain_bit_range(price.repr, PRICE_BITS, cs)
    }
}
