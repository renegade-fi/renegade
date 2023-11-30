//! Defines proof bundles that are passed across worker boundaries

use circuit_types::PlonkProof;
use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_match_settle::ValidMatchSettleStatement,
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_wallet_create::ValidWalletCreateStatement,
    valid_wallet_update::ValidWalletUpdateStatement,
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT};
use serde::{Deserialize, Serialize};

// -----------------
// | Proof Bundles |
// -----------------

/// The response type for a request to generate a proof of `VALID WALLET CREATE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidWalletCreateBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The statement (public variables) used to create the proof
    pub statement: ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies default generics for
/// `GenericValidWalletCreateBundle`
pub type ValidWalletCreateBundle =
    Box<GenericValidWalletCreateBundle<MAX_BALANCES, MAX_BALANCES, MAX_FEES>>;

/// The response type for a request to generate a proof of `VALID WALLET UPDATE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidWalletUpdateBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The statement (public variables) used to prove `VALID WALLET UPDATE`
    pub statement: ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericValidWalletUpdateBundle`
pub type ValidWalletUpdateBundle =
    Box<GenericValidWalletUpdateBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>>;

/// The response type for a request to generate a proof of `VALID REBLIND`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidReblindBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The statement (public variables) used to prover `VALID REBLIND`
    pub statement: ValidReblindStatement,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies default generics for `GenericValidReblindBundle`
pub type ValidReblindBundle =
    Box<GenericValidReblindBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>>;

/// The response type for a request to generate a proof of `VALID COMMITMENTS`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidCommitmentsBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The statement (public variables) used to prove `VALID COMMITMENTS`
    pub statement: ValidCommitmentsStatement,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericValidCommitmentsBundle`
pub type ValidCommitmentsBundle =
    Box<GenericValidCommitmentsBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>;

/// A bundle of the statement, witness commitment, and proof of `VALID MATCH
/// SETTLE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericMatchSettleBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The statement (public variables) used to prove `VALID MATCH SETTLE`
    pub statement: ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that boxes a `GenericValidMatchMpcBundle`
pub type ValidMatchSettleBundle = Box<GenericMatchSettleBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>;

/// The bundle returned by the proof generation module
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
pub enum ProofBundle {
    /// A witness commitment, statement, and proof of `VALID WALLET CREATE`
    ValidWalletCreate(ValidWalletCreateBundle),
    /// A witness commitment, statement, and proof of `VALID REBLIND`
    ValidReblind(ValidReblindBundle),
    /// A witness commitment, statement, and proof of `VALID COMMITMENTS`
    ValidCommitments(ValidCommitmentsBundle),
    /// A witness commitment, statement, and proof of `VALID WALLET UPDATE`
    ValidWalletUpdate(ValidWalletUpdateBundle),
    /// A witness commitment and proof of `VALID MATCH SETTLE`
    ValidMatchSettle(ValidMatchSettleBundle),
}

/// Unsafe cast implementations, will panic if type is incorrect
impl From<ProofBundle> for ValidWalletCreateBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidWalletCreate(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidWalletCreate: {:?}", bundle)
        }
    }
}

impl From<ProofBundle> for ValidReblindBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidReblind(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidReblind: {:?}", bundle);
        }
    }
}

impl From<ProofBundle> for ValidCommitmentsBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidCommitments(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidCommitments: {:?}", bundle)
        }
    }
}

impl From<ProofBundle> for ValidWalletUpdateBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidWalletUpdate(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidWalletUpdate: {:?}", bundle);
        }
    }
}

impl From<ProofBundle> for ValidMatchSettleBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidMatchSettle(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidMatchMpc: {:?}", bundle)
        }
    }
}

// -------------------
// | Proof Groupings |
// -------------------

/// Wraps a proof of `VALID REBLIND` and a proof of `VALID COMMITMENTS` into
/// a common structure so that they may be passed around easily
///
/// We allocate the underlying proofs on the heap to avoid excessive data
/// movement
#[derive(Clone, Debug)]
pub struct OrderValidityProofBundle {
    /// The proof of `VALID REBLIND` for the order's wallet
    pub reblind_proof: Box<ValidReblindBundle>,
    /// The proof of `VALID COMMITMENTS` for the order
    pub commitment_proof: Box<ValidCommitmentsBundle>,
}

impl OrderValidityProofBundle {
    /// Clone the reblind proof out from behind the reference
    pub fn copy_reblind_proof(&self) -> ValidReblindBundle {
        ValidReblindBundle::clone(&self.reblind_proof)
    }

    /// Clone the commitments proof out from behind the reference
    pub fn copy_commitment_proof(&self) -> ValidCommitmentsBundle {
        ValidCommitmentsBundle::clone(&self.commitment_proof)
    }
}

impl Serialize for OrderValidityProofBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.copy_reblind_proof(), self.copy_commitment_proof()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrderValidityProofBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (reblind_proof, commitment_proof) =
            <(ValidReblindBundle, ValidCommitmentsBundle)>::deserialize(deserializer)?;

        Ok(OrderValidityProofBundle {
            reblind_proof: Box::new(reblind_proof),
            commitment_proof: Box::new(commitment_proof),
        })
    }
}

/// Wraps a witness to a proof of `VALID REBLIND` and a witness to a
/// proof of `VALID COMMITMENTS` into a common structure so that they
/// may be passed around easily
///
/// We allocate the underlying witnesses on the heap to avoid excessive data
/// movement
#[derive(Clone, Debug)]
pub struct OrderValidityWitnessBundle {
    /// The witness of `VALID REBLIND` for the order's wallet
    pub reblind_witness: Box<SizedValidReblindWitness>,
    /// The witness of `VALID COMMITMENTS` for the order
    pub commitment_witness: Box<SizedValidCommitmentsWitness>,
}

impl OrderValidityWitnessBundle {
    /// Clone the reblind witness out from behind the reference
    pub fn copy_reblind_witness(&self) -> SizedValidReblindWitness {
        SizedValidReblindWitness::clone(&self.reblind_witness)
    }

    /// Clone the commitment witness out from behind the reference
    pub fn copy_commitment_witness(&self) -> SizedValidCommitmentsWitness {
        SizedValidCommitmentsWitness::clone(&self.commitment_witness)
    }
}

impl Serialize for OrderValidityWitnessBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.copy_reblind_witness(), self.copy_commitment_witness()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrderValidityWitnessBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (reblind_witness, commitment_witness) =
            <(SizedValidReblindWitness, SizedValidCommitmentsWitness)>::deserialize(deserializer)?;

        Ok(OrderValidityWitnessBundle {
            reblind_witness: Box::new(reblind_witness),
            commitment_witness: Box::new(commitment_witness),
        })
    }
}

// ---------
// | Mocks |
// ---------

#[cfg(feature = "mocks")]
pub mod mocks {
    //! Mocks for proof bundle and proof objects
    //!
    //! Note that these mocks are not expected to verify

    use std::iter;

    use ark_ec::CurveGroup;
    use circuit_types::{traits::BaseType, PlonkProof};
    use circuits::zk_circuits::{
        valid_commitments::ValidCommitmentsStatement,
        valid_match_settle::ValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
        valid_wallet_create::ValidWalletCreateStatement,
        valid_wallet_update::ValidWalletUpdateStatement,
    };
    use constants::{Scalar, ScalarField, SystemCurve, SystemCurveGroup};
    use jf_primitives::pcs::prelude::Commitment;
    use mpc_plonk::proof_system::structs::ProofEvaluations;
    use mpc_relation::constants::GATE_WIDTH;
    use rand::thread_rng;

    use super::{
        GenericMatchSettleBundle, GenericValidCommitmentsBundle, GenericValidReblindBundle,
        GenericValidWalletCreateBundle, GenericValidWalletUpdateBundle, OrderValidityProofBundle,
        ValidCommitmentsBundle, ValidMatchSettleBundle, ValidReblindBundle,
        ValidWalletCreateBundle, ValidWalletUpdateBundle,
    };

    /// Create a dummy proof bundle for `VALID WALLET CREATE`
    pub fn dummy_valid_wallet_create_bundle() -> ValidWalletCreateBundle {
        let mut rng = thread_rng();
        let statement =
            ValidWalletCreateStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));
        Box::new(GenericValidWalletCreateBundle { statement, proof: dummy_proof() })
    }

    /// Create a dummy proof bundle for `VALID WALLET UPDATE`
    pub fn dummy_valid_wallet_update_bundle() -> ValidWalletUpdateBundle {
        let mut rng = thread_rng();
        let statement =
            ValidWalletUpdateStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));
        Box::new(GenericValidWalletUpdateBundle { statement, proof: dummy_proof() })
    }

    /// Create a dummy proof bundle for `VALID REBLIND`
    pub fn dummy_valid_reblind_bundle() -> ValidReblindBundle {
        let mut rng = thread_rng();
        let statement =
            ValidReblindStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));
        Box::new(GenericValidReblindBundle { statement, proof: dummy_proof() })
    }

    /// Create a dummy proof bundle for `VALID COMMITMENTS`
    pub fn dummy_valid_commitments_bundle() -> ValidCommitmentsBundle {
        let mut rng = thread_rng();
        let statement =
            ValidCommitmentsStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));
        Box::new(GenericValidCommitmentsBundle { statement, proof: dummy_proof() })
    }

    /// Create a dummy validity proof bundle
    pub fn dummy_validity_proof_bundle() -> OrderValidityProofBundle {
        OrderValidityProofBundle {
            reblind_proof: Box::new(dummy_valid_reblind_bundle()),
            commitment_proof: Box::new(dummy_valid_commitments_bundle()),
        }
    }

    /// Create a dummy proof bundle for `VALID MATCH SETTLE`
    pub fn dummy_valid_match_settle_bundle() -> ValidMatchSettleBundle {
        let mut rng = thread_rng();
        let statement =
            ValidMatchSettleStatement::from_scalars(&mut iter::repeat(Scalar::random(&mut rng)));
        Box::new(GenericMatchSettleBundle { statement, proof: dummy_proof() })
    }

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

    /// Create a dummy commitment to be used as part of a `PlonkProof`
    fn dummy_commitment() -> Commitment<SystemCurve> {
        Commitment(<SystemCurveGroup as CurveGroup>::Affine::default())
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
}
