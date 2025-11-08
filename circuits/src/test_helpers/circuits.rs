//! Circuit helpers for testing

use circuit_types::{
    PlonkCircuit,
    traits::{BaseType, CircuitBaseType, SingleProverCircuit},
};
use constants::Scalar;
use itertools::Itertools;
use mpc_relation::{proof_linking::LinkableCircuit, traits::Circuit};

/// Check that the constraints for a given circuit are satisfied on the
/// given witness, statement pair
pub fn check_constraints_satisfied<C: SingleProverCircuit>(
    witness: &C::Witness,
    statement: &C::Statement,
) -> bool {
    let mut cs = PlonkCircuit::new_turbo_plonk();

    // Create link groups before allocating variables if the circuit defines any
    if let Ok(layout) = C::get_circuit_layout() {
        for (id, group_layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(group_layout));
        }
    }

    // Allocate the witness and statement in the constraint system
    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);
    C::apply_constraints(witness_var, statement_var, &mut cs).unwrap();

    let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}
