//! Mock utilities for testing
//!
//! This module provides dummy proof and linking hint generators for use in
//! tests and mocks.

use ark_ec::{CurveGroup, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use circuit_types::{PlonkLinkProof, PlonkProof, ProofLinkingHint};
use constants::{ScalarField, SystemCurve, SystemCurveGroup};
use jf_primitives::pcs::prelude::{Commitment, UnivariateKzgProof};
use mpc_plonk::proof_system::structs::ProofEvaluations;
use mpc_relation::constants::GATE_WIDTH;

/// Create a dummy R1CS proof
pub fn dummy_proof() -> PlonkProof {
    PlonkProof {
        wires_poly_comms: vec![Default::default(); GATE_WIDTH + 1],
        prod_perm_poly_comm: dummy_commitment(),
        split_quot_poly_comms: vec![Default::default(); GATE_WIDTH + 1],
        opening_proof: dummy_commitment(),
        shifted_opening_proof: dummy_commitment(),
        poly_evals: dummy_poly_evals(),
        plookup_proof: None,
    }
}

/// Create a dummy linking proof to be used as part of a validity bundle
pub fn dummy_link_proof() -> PlonkLinkProof {
    PlonkLinkProof { quotient_commitment: dummy_commitment(), opening_proof: dummy_opening() }
}

/// Create a dummy proof linking hint
pub fn dummy_link_hint() -> ProofLinkingHint {
    ProofLinkingHint {
        linking_wire_poly: DensePolynomial::default(),
        linking_wire_comm: dummy_commitment(),
    }
}

/// Create a dummy commitment to be used as part of a `PlonkProof`
fn dummy_commitment() -> Commitment<SystemCurve> {
    Commitment(<SystemCurveGroup as CurveGroup>::Affine::default())
}

/// Create a dummy opening proof to a KZG commitment
fn dummy_opening() -> UnivariateKzgProof<SystemCurve> {
    UnivariateKzgProof { proof: <SystemCurve as Pairing>::G1Affine::default() }
}

/// Create a set of dummy polynomial evaluations to be used as part of a
/// `PlonkProof`
fn dummy_poly_evals() -> ProofEvaluations<ScalarField> {
    ProofEvaluations {
        wires_evals: vec![Default::default(); GATE_WIDTH + 1],
        wire_sigma_evals: vec![Default::default(); GATE_WIDTH],
        perm_next_eval: ScalarField::default(),
    }
}

#[cfg(all(feature = "mocks", feature = "rkyv"))]
mod bundle_mocks {
    //! Mock utilities for creating validity proof bundles for testing
    use alloy_primitives::Address;
    use constants::Scalar;
    use darkpool_types::state_wrapper::PartialCommitment;

    use super::*;
    use crate::bundles::IntentOnlyValidityBundle;
    use circuits_core::zk_circuits::validity_proofs::intent_only::IntentOnlyValidityStatement;

    /// Create a dummy `IntentOnlyValidityBundle` for storage tests.
    ///
    /// Requires both `mocks` and `rkyv` features.
    pub fn mock_intent_only_validity_bundle() -> IntentOnlyValidityBundle {
        let statement = IntentOnlyValidityStatement {
            owner: Address::ZERO,
            merkle_root: Scalar::zero(),
            old_intent_nullifier: Scalar::zero(),
            new_amount_public_share: Scalar::zero(),
            new_intent_partial_commitment: PartialCommitment {
                private_commitment: Scalar::zero(),
                partial_public_commitment: Scalar::zero(),
            },
            recovery_id: Scalar::zero(),
        };
        IntentOnlyValidityBundle::new(dummy_proof(), statement, dummy_link_hint())
    }
}

#[cfg(all(feature = "mocks", feature = "rkyv"))]
pub use bundle_mocks::mock_intent_only_validity_bundle;
