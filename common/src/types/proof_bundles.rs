//! Defines proof bundles that are passed across worker boundaries

use std::sync::Arc;

use circuits::zk_circuits::{
    valid_commitments::{
        SizedValidCommitmentsWitness, ValidCommitmentsStatement, ValidCommitmentsWitnessCommitment,
    },
    valid_match_mpc::ValidMatchMpcWitnessCommitment,
    valid_reblind::{
        SizedValidReblindWitness, ValidReblindStatement, ValidReblindWitnessCommitment,
    },
    valid_settle::{ValidSettleStatement, ValidSettleWitnessCommitment},
    valid_wallet_create::{ValidWalletCreateStatement, ValidWalletCreateWitnessCommitment},
    valid_wallet_update::{ValidWalletUpdateStatement, ValidWalletUpdateWitnessCommitment},
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT};
use mpc_bulletproof::r1cs::R1CSProof;
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
    /// A commitment to the witness type for `VALID WALLET CREATE`
    pub commitment: ValidWalletCreateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The statement (public variables) used to create the proof
    pub statement: ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: R1CSProof,
}

/// A type alias that specifies default generics for `GenericValidWalletCreateBundle`
pub type ValidWalletCreateBundle =
    GenericValidWalletCreateBundle<MAX_BALANCES, MAX_BALANCES, MAX_FEES>;

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
    /// A commitment to the witness type of `VALID WALLET UPDATE`
    pub commitment:
        ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
    /// The statement (public variables) used to prove `VALID WALLET UPDATE`
    pub statement: ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: R1CSProof,
}

/// A type alias that specifies the default generics for `GenericValidWalletUpdateBundle`
pub type ValidWalletUpdateBundle =
    GenericValidWalletUpdateBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>;

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
    /// A commitment to the witness type of `VALID REBLIND`
    pub commitment:
        ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
    /// The statement (public variables) used to prover `VALID REBLIND`
    pub statement: ValidReblindStatement,
    /// The proof itself
    pub proof: R1CSProof,
}

/// A type alias that specifies default generics for `GenericValidReblindBundle`
pub type ValidReblindBundle =
    GenericValidReblindBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>;

/// The response type for a request to generate a proof of `VALID COMMITMENTS`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidCommitmentsBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// A commitment to the witness type of `VALID COMMITMENTS`
    pub commitment: ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The statement (public variables) used to prove `VALID COMMITMENTS`
    pub statement: ValidCommitmentsStatement,
    /// The proof itself
    pub proof: R1CSProof,
}

/// A type alias that specifies the default generics for `GenericValidCommitmentsBundle`
pub type ValidCommitmentsBundle = GenericValidCommitmentsBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A bundle of the statement, witness commitment, and proof of `VALID MATCH MPC`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchMpcBundle {
    /// A commitment to the witness type of `VALID COMMITMENTS`
    pub commitment: ValidMatchMpcWitnessCommitment,
    /// The statement (public variables) used to prove `VALID COMMITMENTS`
    pub statement: (),
    /// The proof itself
    pub proof: R1CSProof,
}

/// The response type for a request to generate a proof of `VALID SETTLE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidSettleBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 6 * MAX_ORDERS + 4 * MAX_FEES + 1]: Sized,
{
    /// A commitment to the witness type of `VALID SETTLE`
    pub commitment: ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The statement (public variables) used to prove `VALID SETTLE`
    pub statement: ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The proof itself
    pub proof: R1CSProof,
}

/// A type alias that specifies default generics for `GenericValidSettleBundle`
pub type ValidSettleBundle = GenericValidSettleBundle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

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
    /// A witness commitment and proof of `VALID MATCH MPC`
    ValidMatchMpc(ValidMatchMpcBundle),
    /// A witness commitment, statement, and proof of `VALID SETTLE`
    ValidSettle(ValidSettleBundle),
}

/// Unsafe cast implementations, will panic if type is incorrect
impl From<ProofBundle> for ValidWalletCreateBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidWalletCreate(b) = bundle {
            b
        } else {
            panic!(
                "Proof bundle is not of type ValidWalletCreate: {:?}",
                bundle
            )
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
            panic!(
                "Proof bundle is not of type ValidWalletUpdate: {:?}",
                bundle
            );
        }
    }
}

impl From<ProofBundle> for ValidMatchMpcBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidMatchMpc(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidMatchMpc: {:?}", bundle)
        }
    }
}

impl From<ProofBundle> for ValidSettleBundle {
    fn from(bundle: ProofBundle) -> Self {
        if let ProofBundle::ValidSettle(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidSettle: {:?}", bundle)
        }
    }
}

// -------------------
// | Proof Groupings |
// -------------------

/// Wraps a proof of `VALID REBLIND` and a proof of `VALID COMMITMENTS` into
/// a common structure so that they may be passed around easily
///
/// We allocate the underlying proofs on the heap to avoid excessive data movement
#[derive(Clone, Debug)]
pub struct OrderValidityProofBundle {
    /// The proof of `VALID REBLIND` for the order's wallet
    pub reblind_proof: Arc<ValidReblindBundle>,
    /// The proof of `VALID COMMITMENTS` for the order
    pub commitment_proof: Arc<ValidCommitmentsBundle>,
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
            reblind_proof: Arc::new(reblind_proof),
            commitment_proof: Arc::new(commitment_proof),
        })
    }
}

/// Wraps a witness to a proof of `VALID REBLIND` and a witness to a
/// proof of `VALID COMMITMENTS` into a common structure so that they
/// may be passed around easily
///
/// We allocate the underlying witnesses on the heap to avoid excessive data movement
#[derive(Clone, Debug)]
pub struct OrderValidityWitnessBundle {
    /// The witness of `VALID REBLIND` for the order's wallet
    pub reblind_witness: Arc<SizedValidReblindWitness>,
    /// The witness of `VALID COMMITMENTS` for the order
    pub commitment_witness: Arc<SizedValidCommitmentsWitness>,
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
            reblind_witness: Arc::new(reblind_witness),
            commitment_witness: Arc::new(commitment_witness),
        })
    }
}
