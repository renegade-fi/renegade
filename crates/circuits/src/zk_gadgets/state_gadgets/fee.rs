//! Fee gadgets for zero knowledge circuits

use circuit_types::{
    FEE_BITS, PlonkCircuit,
    fee::{FeeRatesVar, FeeTakeVar},
    fixed_point::FixedPointVar,
};
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};

use crate::zk_gadgets::{bits::BitRangeGadget, fixed_point::FixedPointGadget};

/// A gadget for operating on fees
pub struct FeeGadget;
impl FeeGadget {
    /// Constrain a value to be a valid fee
    pub fn constrain_valid_fee(
        fee: FixedPointVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::constrain_bit_range(fee.repr, FEE_BITS, cs)
    }

    /// Compute a fee take for a given receive amount and fee rates type
    pub fn compute_fee_take(
        receive_amount: Variable,
        fee_rates: &FeeRatesVar,
        cs: &mut PlonkCircuit,
    ) -> Result<FeeTakeVar, CircuitError> {
        // Multiply the rates with the receive amount
        let relayer_fee_fp =
            FixedPointGadget::mul_integer(fee_rates.relayer_fee_rate, receive_amount, cs)?;
        let protocol_fee_fp =
            FixedPointGadget::mul_integer(fee_rates.protocol_fee_rate, receive_amount, cs)?;

        // Floor the fees
        let relayer_fee = FixedPointGadget::floor(relayer_fee_fp, cs)?;
        let protocol_fee = FixedPointGadget::floor(protocol_fee_fp, cs)?;
        let take = FeeTakeVar { relayer_fee, protocol_fee };
        Ok(take)
    }

    /// Compute the total fee for a given fee take
    pub fn total_fee(
        fee_take: &FeeTakeVar,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let total_fee = cs.add(fee_take.relayer_fee, fee_take.protocol_fee)?;
        Ok(total_fee)
    }
}

#[cfg(test)]
mod test {
    use circuit_types::{
        FEE_BITS, PlonkCircuit,
        fee::{FeeRates, FeeTake},
        fixed_point::FixedPoint,
        traits::CircuitBaseType,
    };
    use constants::Scalar;
    use eyre::Result;
    use mpc_relation::traits::Circuit;

    use crate::{
        test_helpers::{random_amount, random_fee},
        zk_gadgets::comparators::EqGadget,
    };

    use super::FeeGadget;

    /// Test that compute_fee_take matches the native implementation
    #[test]
    fn test_compute_fee_take_consistency() -> Result<()> {
        // Generate test data
        let relayer_fee_rate = random_fee();
        let protocol_fee_rate = random_fee();
        let receive_amount = random_amount();
        let fee_rates = FeeRates::new(relayer_fee_rate, protocol_fee_rate);
        let expected_fee_take = fee_rates.compute_fee_take(receive_amount);

        // Compute fee take using circuit gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_rates_var = fee_rates.create_witness(&mut cs);
        let receive_amount_var = Scalar::from(receive_amount).create_witness(&mut cs);
        let fee_take_var =
            FeeGadget::compute_fee_take(receive_amount_var, &fee_rates_var, &mut cs)?;

        // Constrain equality and check satisfiability
        let expected_fee_take_var = expected_fee_take.create_witness(&mut cs);
        EqGadget::constrain_eq(&fee_take_var, &expected_fee_take_var, &mut cs)?;

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }

    /// Test that total_fee matches the native implementation
    #[test]
    fn test_total_fee_consistency() -> Result<()> {
        // Generate test data
        let fee_take = FeeTake { relayer_fee: random_amount(), protocol_fee: random_amount() };
        let expected_total = fee_take.total();

        // Compute total fee using circuit gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_take_var = fee_take.create_witness(&mut cs);
        let total_fee_var = FeeGadget::total_fee(&fee_take_var, &mut cs)?;

        // Constrain equality and check satisfiability
        let expected_total_var = expected_total.create_witness(&mut cs);
        cs.enforce_equal(total_fee_var, expected_total_var)?;

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }

    /// Test that constrain_valid_fee correctly rejects invalid fees
    #[test]
    fn test_constrain_valid_fee() -> Result<()> {
        // Create a fee with representation >= 2^FEE_BITS, which exceeds the valid bit
        // range
        let two_to_fee_bits = Scalar::from(2u8).pow(FEE_BITS as u64);
        let invalid_fee_repr = two_to_fee_bits; // Minimum invalid value (exactly 2^FEE_BITS)
        let invalid_fee = FixedPoint::from_repr(invalid_fee_repr);

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_var = invalid_fee.create_witness(&mut cs);

        FeeGadget::constrain_valid_fee(fee_var, &mut cs)?;

        // The circuit should be unsatisfiable because the fee exceeds FEE_BITS
        assert!(cs.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }
}
