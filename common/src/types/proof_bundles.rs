//! Defines proof bundles that are passed across worker boundaries

use std::sync::Arc;

use circuit_types::{PlonkLinkProof, PlonkProof, ProofLinkingHint};
use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_fee_redemption::{SizedValidFeeRedemptionStatement, ValidFeeRedemptionStatement},
    valid_malleable_match_settle_atomic::{
        SizedValidMalleableMatchSettleAtomicStatement, ValidMalleableMatchSettleAtomicStatement,
    },
    valid_match_settle::{SizedValidMatchSettleStatement, ValidMatchSettleStatement},
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomicStatement, ValidMatchSettleAtomicStatement,
    },
    valid_offline_fee_settlement::{
        SizedValidOfflineFeeSettlementStatement, ValidOfflineFeeSettlementStatement,
    },
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_relayer_fee_settlement::{
        SizedValidRelayerFeeSettlementStatement, ValidRelayerFeeSettlementStatement,
    },
    valid_wallet_create::{SizedValidWalletCreateStatement, ValidWalletCreateStatement},
    valid_wallet_update::{SizedValidWalletUpdateStatement, ValidWalletUpdateStatement},
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use serde::{Deserialize, Serialize};

// -----------------
// | Proof Bundles |
// -----------------

/// The response type for a request to generate a proof of `VALID WALLET CREATE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidWalletCreateBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to create the proof
    pub statement: ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies default generics for
/// `GenericValidWalletCreateBundle`
pub type SizedValidWalletCreateBundle = GenericValidWalletCreateBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap allocates a wallet create bundle
pub type ValidWalletCreateBundle = Arc<SizedValidWalletCreateBundle>;

/// The response type for a request to generate a proof of `VALID WALLET UPDATE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidWalletUpdateBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> {
    /// The statement (public variables) used to prove `VALID WALLET UPDATE`
    pub statement: ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericValidWalletUpdateBundle`
pub type SizedValidWalletUpdateBundle =
    GenericValidWalletUpdateBundle<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
/// A type alias that heap-allocates a wallet update bundle
pub type ValidWalletUpdateBundle = Arc<SizedValidWalletUpdateBundle>;

/// The response type for a request to generate a proof of `VALID REBLIND`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidReblindBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
> {
    /// The statement (public variables) used to prover `VALID REBLIND`
    pub statement: ValidReblindStatement,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies default generics for `GenericValidReblindBundle`
pub type SizedValidReblindBundle =
    GenericValidReblindBundle<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
/// A type alias that heap-allocates a reblind bundle
pub type ValidReblindBundle = Arc<SizedValidReblindBundle>;

/// The response type for a request to generate a proof of `VALID COMMITMENTS`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericValidCommitmentsBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID COMMITMENTS`
    pub statement: ValidCommitmentsStatement,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericValidCommitmentsBundle`
pub type SizedValidCommitmentsBundle = GenericValidCommitmentsBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a commitments bundle
pub type ValidCommitmentsBundle = Arc<SizedValidCommitmentsBundle>;

/// A bundle of the statement and proof of `VALID MATCH
/// SETTLE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericMatchSettleBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID MATCH SETTLE`
    pub statement: ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
    /// A proof linking proof of the first party's proof of `VALID COMMITMENTS`
    /// to the proof of `VALID MATCH SETTLE`
    pub commitments_link0: PlonkLinkProof,
    /// A proof linking proof of the second party's proof of `VALID COMMITMENTS`
    /// to the proof of `VALID MATCH SETTLE`
    pub commitments_link1: PlonkLinkProof,
}

/// A type alias that specifies the default generics for
/// `GenericMatchSettleBundle`
pub type SizedValidMatchSettleBundle = GenericMatchSettleBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `ValidMatchMpcBundle`
pub type ValidMatchSettleBundle = Arc<SizedValidMatchSettleBundle>;

/// A bundle of the statement and proof of `VALID MATCH SETTLE ATOMIC`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericMatchSettleAtomicBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID MATCH SETTLE
    /// ATOMIC`
    pub statement: ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericMatchSettleAtomicBundle`
pub type SizedValidMatchSettleAtomicBundle =
    GenericMatchSettleAtomicBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `ValidMatchSettleAtomicBundle`
pub type ValidMatchSettleAtomicBundle = Arc<SizedValidMatchSettleAtomicBundle>;

/// A bundle of the statement and proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericMalleableMatchSettleAtomicBundle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> {
    /// The statement (public variables) used to prove `VALID MALLEABLE MATCH
    /// SETTLE ATOMIC`
    pub statement: ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericMalleableMatchSettleAtomicBundle`
pub type SizedMalleableMatchSettleAtomicBundle =
    GenericMalleableMatchSettleAtomicBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `ValidMalleableMatchSettleAtomicBundle`
pub type ValidMalleableMatchSettleAtomicBundle = Arc<SizedMalleableMatchSettleAtomicBundle>;

/// A bundle of the statement and proof of `VALID RELAYER FEE SETTLEMENT`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericRelayerFeeSettlementBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID RELAYER FEE
    /// SETTLEMENT`
    pub statement: ValidRelayerFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericRelayerFeeSettlementBundle`
pub type SizedRelayerFeeSettlementBundle =
    GenericRelayerFeeSettlementBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `RelayerFeeSettleBundle`
pub type RelayerFeeSettlementBundle = Arc<SizedRelayerFeeSettlementBundle>;

/// A bundle of the statement and proof of `VALID OFFLINE FEE SETTLEMENT`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericOfflineFeeSettlementBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID OFFLINE FEE
    /// SETTLEMENT`
    pub statement: ValidOfflineFeeSettlementStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericOfflineFeeSettlementBundle`
pub type SizedOfflineFeeSettlementBundle =
    GenericOfflineFeeSettlementBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `OfflineFeeSettleBundle`
pub type OfflineFeeSettlementBundle = Arc<SizedOfflineFeeSettlementBundle>;

/// A bundle of the statement and proof of `VALID FEE REDEMPTION`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericFeeRedemptionBundle<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The statement (public variables) used to prove `VALID FEE REDEMPTION`
    pub statement: ValidFeeRedemptionStatement<MAX_BALANCES, MAX_ORDERS>,
    /// The proof itself
    pub proof: PlonkProof,
}

/// A type alias that specifies the default generics for
/// `GenericFeeRedemptionBundle`
pub type SizedFeeRedemptionBundle = GenericFeeRedemptionBundle<MAX_BALANCES, MAX_ORDERS>;
/// A type alias that heap-allocates a `FeeRedemptionBundle`
pub type FeeRedemptionBundle = Arc<SizedFeeRedemptionBundle>;

/// The proof bundle returned by the proof generation module
#[derive(Clone, Debug)]
pub struct ProofBundle {
    /// The underlying r1cs satisfaction proof
    pub proof: R1CSProofBundle,
    /// The proof linking hint returned by the proof
    pub link_hint: ProofLinkingHint,
}

impl ProofBundle {
    /// Create a new proof bundle from a `VALID WALLET CREATE` proof
    pub fn new_valid_wallet_create(
        statement: SizedValidWalletCreateStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidWalletCreate(Arc::new(GenericValidWalletCreateBundle {
                statement,
                proof,
            })),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID WALLET UPDATE` proof
    pub fn new_valid_wallet_update(
        statement: SizedValidWalletUpdateStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidWalletUpdate(Arc::new(GenericValidWalletUpdateBundle {
                statement,
                proof,
            })),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID REBLIND` proof
    pub fn new_valid_reblind(
        statement: ValidReblindStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidReblind(Arc::new(GenericValidReblindBundle {
                statement,
                proof,
            })),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID COMMITMENTS` proof
    pub fn new_valid_commitments(
        statement: ValidCommitmentsStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidCommitments(Arc::new(GenericValidCommitmentsBundle {
                statement,
                proof,
            })),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID MATCH SETTLE` proof
    pub fn new_valid_match_settle(
        statement: SizedValidMatchSettleStatement,
        proof: PlonkProof,
        party0_link: PlonkLinkProof,
        party1_link: PlonkLinkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidMatchSettle(Arc::new(GenericMatchSettleBundle {
                statement,
                proof,
                commitments_link0: party0_link,
                commitments_link1: party1_link,
            })),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID MATCH SETTLE ATOMIC` proof
    pub fn new_valid_match_settle_atomic(
        statement: SizedValidMatchSettleAtomicStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidMatchSettleAtomic(Arc::new(
                GenericMatchSettleAtomicBundle { statement, proof },
            )),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID MALLEABLE MATCH SETTLE ATOMIC`
    /// proof
    pub fn new_valid_malleable_match_settle_atomic(
        statement: SizedValidMalleableMatchSettleAtomicStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidMalleableMatchSettleAtomic(Arc::new(
                GenericMalleableMatchSettleAtomicBundle { statement, proof },
            )),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID RELAYER FEE SETTLEMENT` proof
    pub fn new_valid_relayer_fee_settlement(
        statement: SizedValidRelayerFeeSettlementStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidRelayerFeeSettlement(Arc::new(
                GenericRelayerFeeSettlementBundle { statement, proof },
            )),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID OFFLINE FEE SETTLEMENT` proof
    pub fn new_valid_offline_fee_settlement(
        statement: SizedValidOfflineFeeSettlementStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidOfflineFeeSettlement(Arc::new(
                GenericOfflineFeeSettlementBundle { statement, proof },
            )),
            link_hint,
        }
    }

    /// Create a new proof bundle from a `VALID FEE REDEMPTION` proof
    pub fn new_valid_fee_redemption(
        statement: SizedValidFeeRedemptionStatement,
        proof: PlonkProof,
        link_hint: ProofLinkingHint,
    ) -> Self {
        ProofBundle {
            proof: R1CSProofBundle::ValidFeeRedemption(Arc::new(GenericFeeRedemptionBundle {
                statement,
                proof,
            })),
            link_hint,
        }
    }
}

/// The bundle type returned by the proof generation module
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
pub enum R1CSProofBundle {
    /// A statement and proof of `VALID WALLET CREATE`
    ValidWalletCreate(ValidWalletCreateBundle),
    /// A statement and proof of `VALID REBLIND`
    ValidReblind(ValidReblindBundle),
    /// A statement and proof of `VALID COMMITMENTS`
    ValidCommitments(ValidCommitmentsBundle),
    /// A statement and proof of `VALID WALLET UPDATE`
    ValidWalletUpdate(ValidWalletUpdateBundle),
    /// A statement and proof of `VALID MATCH SETTLE`
    ValidMatchSettle(ValidMatchSettleBundle),
    /// A statement and proof of `VALID MATCH SETTLE ATOMIC`
    ValidMatchSettleAtomic(ValidMatchSettleAtomicBundle),
    /// A statement and proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
    ValidMalleableMatchSettleAtomic(ValidMalleableMatchSettleAtomicBundle),
    /// A statement and proof of `VALID RELAYER FEE SETTLEMENT`
    ValidRelayerFeeSettlement(RelayerFeeSettlementBundle),
    /// A statement and proof of `VALID OFFLINE FEE SETTLEMENT`
    ValidOfflineFeeSettlement(OfflineFeeSettlementBundle),
    /// A statement and proof of `VALID FEE REDEMPTION`
    ValidFeeRedemption(FeeRedemptionBundle),
}

/// Unsafe cast implementations, will panic if type is incorrect
impl From<R1CSProofBundle> for ValidWalletCreateBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidWalletCreate(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidWalletCreate: {:?}", bundle)
        }
    }
}

impl From<R1CSProofBundle> for ValidReblindBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidReblind(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidReblind: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for ValidCommitmentsBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidCommitments(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidCommitments: {:?}", bundle)
        }
    }
}

impl From<R1CSProofBundle> for ValidWalletUpdateBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidWalletUpdate(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidWalletUpdate: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for ValidMatchSettleBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidMatchSettle(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidMatchMpc: {:?}", bundle)
        }
    }
}

impl From<R1CSProofBundle> for ValidMatchSettleAtomicBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidMatchSettleAtomic(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidMatchSettleAtomic: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for ValidMalleableMatchSettleAtomicBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidMalleableMatchSettleAtomic(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidMalleableMatchSettleAtomic: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for RelayerFeeSettlementBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidRelayerFeeSettlement(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidRelayerFeeSettlement: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for OfflineFeeSettlementBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidOfflineFeeSettlement(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidOfflineFeeSettlement: {:?}", bundle);
        }
    }
}

impl From<R1CSProofBundle> for FeeRedemptionBundle {
    fn from(bundle: R1CSProofBundle) -> Self {
        if let R1CSProofBundle::ValidFeeRedemption(b) = bundle {
            b
        } else {
            panic!("Proof bundle is not of type ValidFeeRedemption: {:?}", bundle);
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
    pub reblind_proof: ValidReblindBundle,
    /// The proof of `VALID COMMITMENTS` for the order
    pub commitment_proof: ValidCommitmentsBundle,
    /// A linking proof of the reblind and commitments proofs in this struct
    pub linking_proof: PlonkLinkProof,
}

impl OrderValidityProofBundle {
    /// Clone the reblind proof out from behind the reference
    pub fn copy_reblind_proof(&self) -> SizedValidReblindBundle {
        SizedValidReblindBundle::clone(&self.reblind_proof)
    }

    /// Clone the commitments proof out from behind the reference
    pub fn copy_commitment_proof(&self) -> SizedValidCommitmentsBundle {
        SizedValidCommitmentsBundle::clone(&self.commitment_proof)
    }
}

impl Serialize for OrderValidityProofBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.copy_reblind_proof(), self.copy_commitment_proof(), self.linking_proof.clone())
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrderValidityProofBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (reblind_proof, commitment_proof, linking_proof) =
            <(SizedValidReblindBundle, SizedValidCommitmentsBundle, PlonkLinkProof)>::deserialize(
                deserializer,
            )?;

        Ok(OrderValidityProofBundle {
            reblind_proof: Arc::new(reblind_proof),
            commitment_proof: Arc::new(commitment_proof),
            linking_proof,
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
    pub reblind_witness: Arc<SizedValidReblindWitness>,
    /// The witness of `VALID COMMITMENTS` for the order
    pub commitment_witness: Arc<SizedValidCommitmentsWitness>,
    /// The proof-linking hint for the `VALID COMMITMENTS` proof,
    ///
    /// We only need to keep this hint around as the `VALID REBLIND` proof's
    /// hint will have already been used
    pub commitment_linking_hint: Arc<ProofLinkingHint>,
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

    /// Clone the linking hint out from behind the reference
    pub fn copy_commitment_linking_hint(&self) -> ProofLinkingHint {
        ProofLinkingHint::clone(&self.commitment_linking_hint)
    }
}

impl Serialize for OrderValidityWitnessBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (
            self.copy_reblind_witness(),
            self.copy_commitment_witness(),
            self.copy_commitment_linking_hint(),
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrderValidityWitnessBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (reblind_witness, commitment_witness, linking_hint) = <(
            SizedValidReblindWitness,
            SizedValidCommitmentsWitness,
            ProofLinkingHint,
        )>::deserialize(
            deserializer
        )?;

        Ok(OrderValidityWitnessBundle {
            reblind_witness: Arc::new(reblind_witness),
            commitment_witness: Arc::new(commitment_witness),
            commitment_linking_hint: Arc::new(linking_hint),
        })
    }
}

/// A bundle of proofs for the atomic match settlement proof
#[derive(Clone, Debug)]
pub struct AtomicMatchSettleBundle {
    /// The proof of `VALID MATCH SETTLE ATOMIC` for the matched orders
    pub atomic_match_proof: ValidMatchSettleAtomicBundle,
    /// The linking proof of the atomic match proof to the commitment proof of
    /// the internal party
    pub commitments_link: PlonkLinkProof,
}

impl AtomicMatchSettleBundle {
    /// Clone the atomic match proof out from behind the `Arc`
    pub fn copy_atomic_match_proof(&self) -> SizedValidMatchSettleAtomicBundle {
        SizedValidMatchSettleAtomicBundle::clone(&self.atomic_match_proof)
    }
}

impl Serialize for AtomicMatchSettleBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.copy_atomic_match_proof(), self.commitments_link.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AtomicMatchSettleBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (atomic_match_proof, commitments_link) =
            <(SizedValidMatchSettleAtomicBundle, PlonkLinkProof)>::deserialize(deserializer)?;

        Ok(AtomicMatchSettleBundle {
            atomic_match_proof: Arc::new(atomic_match_proof),
            commitments_link,
        })
    }
}

/// A bundle of proofs for the malleable atomic match settlement proof
#[derive(Clone, Debug)]
pub struct MalleableAtomicMatchSettleBundle {
    /// The proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
    pub atomic_match_proof: ValidMalleableMatchSettleAtomicBundle,
    /// The linking proof of the atomic match proof to the commitment proof of
    /// the internal party
    pub commitments_link: PlonkLinkProof,
}

impl MalleableAtomicMatchSettleBundle {
    /// Clone the atomic match proof out from behind the `Arc`
    pub fn copy_atomic_match_proof(&self) -> SizedMalleableMatchSettleAtomicBundle {
        SizedMalleableMatchSettleAtomicBundle::clone(&self.atomic_match_proof)
    }
}

impl Serialize for MalleableAtomicMatchSettleBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.copy_atomic_match_proof(), self.commitments_link.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MalleableAtomicMatchSettleBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (atomic_match_proof, commitments_link) =
            <(SizedMalleableMatchSettleAtomicBundle, PlonkLinkProof)>::deserialize(deserializer)?;

        Ok(MalleableAtomicMatchSettleBundle {
            atomic_match_proof: Arc::new(atomic_match_proof),
            commitments_link,
        })
    }
}

// ---------
// | Mocks |
// ---------

/// Mocks for proof bundle and proof objects
///
/// Note that these mocks are not expected to verify
#[cfg(feature = "mocks")]
pub mod mocks {

    use std::{iter, sync::Arc};

    use ark_ec::{CurveGroup, pairing::Pairing};
    use ark_poly::univariate::DensePolynomial;
    use circuit_types::{PlonkLinkProof, PlonkProof, ProofLinkingHint, traits::BaseType};
    use circuits::zk_circuits::{
        valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
        valid_fee_redemption::ValidFeeRedemptionStatement,
        valid_match_settle::ValidMatchSettleStatement,
        valid_offline_fee_settlement::ValidOfflineFeeSettlementStatement,
        valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
        valid_relayer_fee_settlement::ValidRelayerFeeSettlementStatement,
        valid_wallet_create::ValidWalletCreateStatement,
        valid_wallet_update::ValidWalletUpdateStatement,
    };
    use constants::{Scalar, ScalarField, SystemCurve, SystemCurveGroup};
    use jf_primitives::pcs::prelude::{Commitment, UnivariateKzgProof};
    use mpc_plonk::proof_system::structs::ProofEvaluations;
    use mpc_relation::constants::GATE_WIDTH;

    use super::{
        OrderValidityProofBundle, OrderValidityWitnessBundle, SizedFeeRedemptionBundle,
        SizedOfflineFeeSettlementBundle, SizedRelayerFeeSettlementBundle,
        SizedValidCommitmentsBundle, SizedValidMatchSettleBundle, SizedValidReblindBundle,
        SizedValidWalletCreateBundle, SizedValidWalletUpdateBundle,
    };

    /// Create a dummy proof bundle for `VALID WALLET CREATE`
    pub fn dummy_valid_wallet_create_bundle() -> SizedValidWalletCreateBundle {
        let statement = ValidWalletCreateStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedValidWalletCreateBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID WALLET UPDATE`
    pub fn dummy_valid_wallet_update_bundle() -> SizedValidWalletUpdateBundle {
        let statement = ValidWalletUpdateStatement::from_scalars(&mut iter::repeat(Scalar::one()));

        SizedValidWalletUpdateBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID REBLIND`
    pub fn dummy_valid_reblind_bundle() -> SizedValidReblindBundle {
        let statement = ValidReblindStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedValidReblindBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID COMMITMENTS`
    pub fn dummy_valid_commitments_bundle() -> SizedValidCommitmentsBundle {
        let statement = ValidCommitmentsStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedValidCommitmentsBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID RELAYER FEE SETTLEMENT`
    pub fn dummy_relayer_fee_settlement_bundle() -> SizedRelayerFeeSettlementBundle {
        let statement =
            ValidRelayerFeeSettlementStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedRelayerFeeSettlementBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID OFFLINE FEE SETTLEMENT`
    pub fn dummy_offline_fee_settlement_bundle() -> SizedOfflineFeeSettlementBundle {
        let statement =
            ValidOfflineFeeSettlementStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedOfflineFeeSettlementBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy proof bundle for `VALID FEE REDEMPTION`
    pub fn dummy_valid_fee_redemption_bundle() -> SizedFeeRedemptionBundle {
        let statement = ValidFeeRedemptionStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedFeeRedemptionBundle { statement, proof: dummy_proof() }
    }

    /// Create a dummy validity proof bundle
    pub fn dummy_validity_proof_bundle() -> OrderValidityProofBundle {
        OrderValidityProofBundle {
            reblind_proof: Arc::new(dummy_valid_reblind_bundle()),
            commitment_proof: Arc::new(dummy_valid_commitments_bundle()),
            linking_proof: dummy_link_proof(),
        }
    }

    /// Create a dummy witness to a validity proof bundle
    pub fn dummy_validity_witness_bundle() -> OrderValidityWitnessBundle {
        let mut iter = iter::repeat(Scalar::one());
        OrderValidityWitnessBundle {
            reblind_witness: Arc::new(SizedValidReblindWitness::from_scalars(&mut iter)),
            commitment_witness: Arc::new(SizedValidCommitmentsWitness::from_scalars(&mut iter)),
            commitment_linking_hint: Arc::new(dummy_link_hint()),
        }
    }

    /// Create a dummy proof bundle for `VALID MATCH SETTLE`
    pub fn dummy_valid_match_settle_bundle() -> SizedValidMatchSettleBundle {
        let statement = ValidMatchSettleStatement::from_scalars(&mut iter::repeat(Scalar::one()));
        SizedValidMatchSettleBundle {
            statement,
            proof: dummy_proof(),
            commitments_link0: dummy_link_proof(),
            commitments_link1: dummy_link_proof(),
        }
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
}
