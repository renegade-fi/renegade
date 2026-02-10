//! Rkyv remotes for Plonk proof types.
//!
//! This module defines remote type shims for `PlonkProof` and supporting
//! sub-types used inside it.
#![allow(clippy::missing_docs_in_private_items)]

use ark_bn254::FrConfig;
use ark_bn254::{FqConfig, G1Affine};
use ark_ff::{BigInt, Fp, MontBackend};
use ark_poly::univariate::DensePolynomial;
use circuit_types::{PlonkProof, PolynomialCommitment, ProofLinkingHint};
use constants::ScalarField;
use mpc_plonk::proof_system::structs::{
    PlookupProof as GenericPlookupProof, ProofEvaluations as GenericProofEvaluations,
};
use rkyv::{
    Archive, Deserialize, Serialize,
    with::{Map, Skip},
};

/// The number of u64 limbs in an arkworks BN254 scalar field element.
const SCALAR_LIMBS: usize = 4;

/// The concrete proof-evaluations type used by `PlonkProof`.
type PlonkProofEvaluations = GenericProofEvaluations<ScalarField>;

// --- ScalarField --- //

#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = BigInt<SCALAR_LIMBS>)]
pub(crate) struct BigIntDef(pub [u64; SCALAR_LIMBS]);

impl From<BigIntDef> for BigInt<SCALAR_LIMBS> {
    fn from(value: BigIntDef) -> Self {
        BigInt(value.0)
    }
}

#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>)]
pub(crate) struct ScalarFieldDef(
    #[rkyv(with = BigIntDef)] pub BigInt<SCALAR_LIMBS>,
    pub std::marker::PhantomData<MontBackend<FrConfig, SCALAR_LIMBS>>,
);

impl From<ScalarFieldDef> for Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS> {
    fn from(value: ScalarFieldDef) -> Self {
        Fp(value.0, value.1)
    }
}

// --- Commitment --- //

#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = Fp<MontBackend<FqConfig, SCALAR_LIMBS>, SCALAR_LIMBS>)]
pub(crate) struct BaseFieldDef(
    #[rkyv(with = BigIntDef)] pub BigInt<SCALAR_LIMBS>,
    pub std::marker::PhantomData<MontBackend<FqConfig, SCALAR_LIMBS>>,
);

impl From<BaseFieldDef> for Fp<MontBackend<FqConfig, SCALAR_LIMBS>, SCALAR_LIMBS> {
    fn from(value: BaseFieldDef) -> Self {
        Fp(value.0, value.1)
    }
}

/// Remote type shim for `ark_bn254::G1Affine`.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
#[rkyv(remote = G1Affine)]
#[rkyv(archived = ArchivedG1AffineDef)]
pub struct G1AffineDef {
    /// The x coordinate.
    #[rkyv(with = BaseFieldDef)]
    pub x: ark_bn254::Fq,
    /// The y coordinate.
    #[rkyv(with = BaseFieldDef)]
    pub y: ark_bn254::Fq,
    /// Whether the point is at infinity.
    pub infinity: bool,
}

impl From<G1AffineDef> for G1Affine {
    fn from(value: G1AffineDef) -> Self {
        if value.infinity {
            G1Affine::identity()
        } else {
            G1Affine::new_unchecked(value.x, value.y)
        }
    }
}

impl From<G1Affine> for G1AffineDef {
    fn from(value: G1Affine) -> Self {
        Self { x: value.x, y: value.y, infinity: value.infinity }
    }
}

/// Remote type shim for `PolynomialCommitment`.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PolynomialCommitment)]
#[rkyv(archived = ArchivedCommitmentDef)]
pub struct CommitmentDef(
    /// The affine curve point backing the commitment.
    #[rkyv(with = G1AffineDef)]
    pub G1Affine,
);

impl From<CommitmentDef> for PolynomialCommitment {
    fn from(value: CommitmentDef) -> Self {
        value.0.into()
    }
}

// --- Linking hint --- //

/// Remote shim for `DensePolynomial<ScalarField>`.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = DensePolynomial<ScalarField>)]
#[rkyv(archived = ArchivedDensePolynomialDef)]
pub struct DensePolynomialDef {
    /// Coefficients of the polynomial in ascending order.
    #[rkyv(with = Map<ScalarFieldDef>)]
    pub coeffs: Vec<ScalarField>,
}

impl From<DensePolynomialDef> for DensePolynomial<ScalarField> {
    fn from(value: DensePolynomialDef) -> Self {
        DensePolynomial { coeffs: value.coeffs }
    }
}

/// Remote shim for `ProofLinkingHint`.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofLinkingHint)]
#[rkyv(archived = ArchivedProofLinkingHintDef)]
pub struct ProofLinkingHintDef {
    /// The linking wire polynomial.
    #[rkyv(with = DensePolynomialDef)]
    pub linking_wire_poly: DensePolynomial<ScalarField>,
    /// Commitment to the linking wire polynomial.
    #[rkyv(with = CommitmentDef)]
    pub linking_wire_comm: circuit_types::PolynomialCommitment,
}

impl From<ProofLinkingHintDef> for ProofLinkingHint {
    fn from(value: ProofLinkingHintDef) -> Self {
        Self {
            linking_wire_poly: value.linking_wire_poly,
            linking_wire_comm: value.linking_wire_comm,
        }
    }
}

// --- ProofEvaluations --- //

/// Remote type shim for Plonk proof polynomial evaluations.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PlonkProofEvaluations)]
#[rkyv(archived = ArchivedProofEvaluationsDef)]
pub struct ProofEvaluationsDef {
    /// Wire witness polynomial evaluations at challenge `zeta`.
    #[rkyv(with = Map<ScalarFieldDef>)]
    pub wires_evals: Vec<ScalarField>,
    /// Wire permutation polynomial evaluations at challenge `zeta`.
    #[rkyv(with = Map<ScalarFieldDef>)]
    pub wire_sigma_evals: Vec<ScalarField>,
    /// Permutation product polynomial evaluation at challenge `zeta * g`.
    #[rkyv(with = ScalarFieldDef)]
    pub perm_next_eval: ScalarField,
}

impl From<ProofEvaluationsDef> for PlonkProofEvaluations {
    fn from(value: ProofEvaluationsDef) -> Self {
        Self {
            wires_evals: value.wires_evals,
            wire_sigma_evals: value.wire_sigma_evals,
            perm_next_eval: value.perm_next_eval,
        }
    }
}

// --- PlonkProof --- //

/// Remote type shim for `PlonkProof`.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PlonkProof)]
#[rkyv(archived = ArchivedPlonkProofDef)]
pub struct PlonkProofDef {
    /// Commitments to wire witness polynomials.
    #[rkyv(with = Map<CommitmentDef>)]
    pub wires_poly_comms: Vec<PolynomialCommitment>,
    /// Commitment for the wire permutation argument.
    #[rkyv(with = CommitmentDef)]
    pub prod_perm_poly_comm: PolynomialCommitment,
    /// Commitments to split quotient polynomials.
    #[rkyv(with = Map<CommitmentDef>)]
    pub split_quot_poly_comms: Vec<PolynomialCommitment>,
    /// Aggregated opening proof at challenge `zeta`.
    #[rkyv(with = CommitmentDef)]
    pub opening_proof: PolynomialCommitment,
    /// Aggregated opening proof at challenge `zeta * g`.
    #[rkyv(with = CommitmentDef)]
    pub shifted_opening_proof: PolynomialCommitment,
    /// Polynomial evaluations bundled with the proof.
    #[rkyv(with = ProofEvaluationsDef)]
    pub poly_evals: PlonkProofEvaluations,
    /// Optional plookup proof.
    ///
    /// This is skipped for relayer archival because only TurboPlonk (no
    /// plookup payload) is currently supported.
    #[rkyv(with = Skip)]
    pub plookup_proof: Option<GenericPlookupProof<constants::SystemCurve>>,
}

impl From<PlonkProofDef> for PlonkProof {
    fn from(value: PlonkProofDef) -> Self {
        PlonkProof {
            wires_poly_comms: value.wires_poly_comms,
            prod_perm_poly_comm: value.prod_perm_poly_comm,
            split_quot_poly_comms: value.split_quot_poly_comms,
            opening_proof: value.opening_proof,
            shifted_opening_proof: value.shifted_opening_proof,
            poly_evals: value.poly_evals,
            plookup_proof: None,
        }
    }
}
