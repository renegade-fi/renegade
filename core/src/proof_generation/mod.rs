//! The proof generation worker handles the core of generating single-prover
//! proofs for wallet updates

use std::sync::Arc;

use circuits::zk_circuits::{
    valid_commitments::{ValidCommitments, ValidCommitmentsWitness},
    valid_reblind::{ValidReblind, ValidReblindWitness},
    valid_settle::{ValidSettleStatement, ValidSettleWitness},
    valid_wallet_create::{ValidWalletCreateStatement, ValidWalletCreateWitness},
    valid_wallet_update::{ValidWalletUpdateStatement, ValidWalletUpdateWitness},
};
use serde::{Deserialize, Serialize};

use crate::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};

use self::jobs::{ValidCommitmentsBundle, ValidReblindBundle};
pub mod error;
pub mod jobs;
pub mod proof_manager;
pub mod worker;

// ----------------------------------
// | Circuit Default Generics Types |
// ----------------------------------

/// A witness to `VALID WALLET CREATE` with default size parameters attached
pub type SizedValidWalletCreateWitness =
    ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A statement for `VALID WALLET CREATE` with default size parameters attached
pub type SizedValidWalletCreateStatement =
    ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A `VALID WALLET UPDATE` witness with default const generic sizing parameters
pub type SizedValidWalletUpdateWitness =
    ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID WALLET UPDATE` statement with default const generic sizing parameters
pub type SizedValidWalletUpdateStatement =
    ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A `VALID COMMITMENTS` witness with default const generic sizing parameters
pub type SizedValidCommitmentsWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// `VALID COMMITMENTS` with default state element sizing
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A `VALID REBLIND` circuit with default const generic sizing parameters
pub type SizedValidReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID REBLIND` witness with default const generic sizing parameters
pub type SizedValidReblindWitness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// A `VALID SETTLE` witness with default const generic sizing parameters
pub type SizedValidSettleWitness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A `VALID SETTLE` statement with default const generic sizing parameters
pub type SizedValidSettleStatement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

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
