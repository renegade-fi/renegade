//! Proof bundle types
//!
//! This module contains types for bundling proofs together with their
//! statements.

use circuit_types::{PlonkLinkProof, PlonkProof, ProofLinkingHint};
use circuits_core::zk_circuits::{
    fees::{
        valid_note_redemption::ValidNoteRedemptionStatement,
        valid_private_protocol_fee_payment::ValidPrivateProtocolFeePaymentStatement,
        valid_private_relayer_fee_payment::ValidPrivateRelayerFeePaymentStatement,
        valid_public_protocol_fee_payment::ValidPublicProtocolFeePaymentStatement,
        valid_public_relayer_fee_payment::ValidPublicRelayerFeePaymentStatement,
    },
    settlement::{
        intent_and_balance_bounded_settlement::IntentAndBalanceBoundedSettlementStatement,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementStatement,
        intent_and_balance_public_settlement::IntentAndBalancePublicSettlementStatement,
        intent_only_bounded_settlement::IntentOnlyBoundedSettlementStatement,
        intent_only_public_settlement::IntentOnlyPublicSettlementStatement,
    },
    valid_balance_create::ValidBalanceCreateStatement,
    valid_deposit::ValidDepositStatement,
    valid_order_cancellation::ValidOrderCancellationStatement,
    valid_withdrawal::ValidWithdrawalStatement,
    validity_proofs::{
        intent_and_balance::IntentAndBalanceValidityStatement,
        intent_and_balance_first_fill::IntentAndBalanceFirstFillValidityStatement,
        intent_only::IntentOnlyValidityStatement,
        intent_only_first_fill::IntentOnlyFirstFillValidityStatement,
        new_output_balance::NewOutputBalanceValidityStatement,
        output_balance::OutputBalanceValidityStatement,
    },
};
use serde::{Deserialize, Serialize};

/// The inner proof bundle type containing the actual data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundleInner<Statement> {
    /// The proof
    pub proof: PlonkProof,
    /// The statement for this proof
    pub statement: Statement,
}

/// The inner proof bundle (with hint) type containing the actual data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAndHintBundleInner<Statement> {
    /// The proof
    pub proof: PlonkProof,
    /// The statement for this proof
    pub statement: Statement,
    /// The linking hint for this proof
    pub linking_hint: ProofLinkingHint,
}

/// A heap-allocated proof bundle
///
/// This type boxes the inner proof bundle to avoid large stack allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofBundle<Statement>(Box<ProofBundleInner<Statement>>);

impl<Statement> ProofBundle<Statement> {
    /// Create a new proof bundle from its components
    pub fn new(proof: PlonkProof, statement: Statement) -> Self {
        Self(Box::new(ProofBundleInner { proof, statement }))
    }

    /// Create a new proof bundle from an inner type
    pub fn from_inner(inner: ProofBundleInner<Statement>) -> Self {
        Self(Box::new(inner))
    }

    /// Consume the bundle and return the inner data
    pub fn into_inner(self) -> ProofBundleInner<Statement> {
        *self.0
    }
}

impl<Statement> AsRef<ProofBundleInner<Statement>> for ProofBundle<Statement> {
    fn as_ref(&self) -> &ProofBundleInner<Statement> {
        &self.0
    }
}

impl<Statement> std::ops::Deref for ProofBundle<Statement> {
    type Target = ProofBundleInner<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A heap-allocated proof bundle (with hint)
///
/// This type boxes the inner proof bundle to avoid large stack allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofAndHintBundle<Statement>(Box<ProofAndHintBundleInner<Statement>>);

impl<Statement> ProofAndHintBundle<Statement> {
    /// Create a new proof bundle from its components
    pub fn new(proof: PlonkProof, statement: Statement, linking_hint: ProofLinkingHint) -> Self {
        Self(Box::new(ProofAndHintBundleInner { proof, statement, linking_hint }))
    }

    /// Create a new proof bundle from an inner type
    pub fn from_inner(inner: ProofAndHintBundleInner<Statement>) -> Self {
        Self(Box::new(inner))
    }

    /// Consume the bundle and return the inner data
    pub fn into_inner(self) -> ProofAndHintBundleInner<Statement> {
        *self.0
    }
}

impl<Statement> AsRef<ProofAndHintBundleInner<Statement>> for ProofAndHintBundle<Statement> {
    fn as_ref(&self) -> &ProofAndHintBundleInner<Statement> {
        &self.0
    }
}

impl<Statement> std::ops::Deref for ProofAndHintBundle<Statement> {
    type Target = ProofAndHintBundleInner<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The inner settlement proof bundle type containing a proof, statement, and
/// link proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentOnlySettlementProofBundleInner<Statement> {
    /// The proof
    pub proof: PlonkProof,
    /// The statement for this proof
    pub statement: Statement,
    /// The linking proof
    pub link_proof: PlonkLinkProof,
}

/// A heap-allocated settlement proof bundle
///
/// This type boxes the inner proof bundle to avoid large stack allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntentOnlySettlementProofBundle<Statement>(
    Box<IntentOnlySettlementProofBundleInner<Statement>>,
);
impl<Statement> IntentOnlySettlementProofBundle<Statement> {
    /// Create a new settlement proof bundle from its components
    pub fn new(proof: PlonkProof, statement: Statement, link_proof: PlonkLinkProof) -> Self {
        Self(Box::new(IntentOnlySettlementProofBundleInner { proof, statement, link_proof }))
    }

    /// Create a new settlement proof bundle from an inner type
    pub fn from_inner(inner: IntentOnlySettlementProofBundleInner<Statement>) -> Self {
        Self(Box::new(inner))
    }

    /// Consume the bundle and return the inner data
    pub fn into_inner(self) -> IntentOnlySettlementProofBundleInner<Statement> {
        *self.0
    }
}

impl<Statement> AsRef<IntentOnlySettlementProofBundleInner<Statement>>
    for IntentOnlySettlementProofBundle<Statement>
{
    fn as_ref(&self) -> &IntentOnlySettlementProofBundleInner<Statement> {
        &self.0
    }
}

impl<Statement> std::ops::Deref for IntentOnlySettlementProofBundle<Statement> {
    type Target = IntentOnlySettlementProofBundleInner<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The inner public settlement proof bundle type containing a proof,
/// statement, and both linking proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSettlementProofBundleInner<Statement> {
    /// The proof
    pub proof: PlonkProof,
    /// The statement for this proof
    pub statement: Statement,
    /// The validity linking proof
    pub validity_link_proof: PlonkLinkProof,
    /// The output balance linking proof
    pub output_balance_link_proof: PlonkLinkProof,
}

/// A heap-allocated public settlement proof bundle
///
/// This type boxes the inner proof bundle to avoid large stack allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicSettlementProofBundle<Statement>(Box<PublicSettlementProofBundleInner<Statement>>);

impl<Statement> PublicSettlementProofBundle<Statement> {
    /// Create a new public settlement proof bundle from its components
    pub fn new(
        proof: PlonkProof,
        statement: Statement,
        validity_link_proof: PlonkLinkProof,
        output_balance_link_proof: PlonkLinkProof,
    ) -> Self {
        Self(Box::new(PublicSettlementProofBundleInner {
            proof,
            statement,
            validity_link_proof,
            output_balance_link_proof,
        }))
    }

    /// Create a new public settlement proof bundle from an inner type
    pub fn from_inner(inner: PublicSettlementProofBundleInner<Statement>) -> Self {
        Self(Box::new(inner))
    }

    /// Consume the bundle and return the inner data
    pub fn into_inner(self) -> PublicSettlementProofBundleInner<Statement> {
        *self.0
    }
}

impl<Statement> AsRef<PublicSettlementProofBundleInner<Statement>>
    for PublicSettlementProofBundle<Statement>
{
    fn as_ref(&self) -> &PublicSettlementProofBundleInner<Statement> {
        &self.0
    }
}

impl<Statement> std::ops::Deref for PublicSettlementProofBundle<Statement> {
    type Target = PublicSettlementProofBundleInner<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The inner private settlement proof bundle type containing a proof,
/// statement, and multiple link proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSettlementProofBundleInner<Statement> {
    /// The proof
    pub proof: PlonkProof,
    /// The statement for this proof
    pub statement: Statement,
    /// Party 0's validity linking proof
    pub validity_link_proof_0: PlonkLinkProof,
    /// Party 1's validity linking proof
    pub validity_link_proof_1: PlonkLinkProof,
    /// Party 0's output balance linking proof
    pub output_balance_link_proof_0: PlonkLinkProof,
    /// Party 1's output balance linking proof
    pub output_balance_link_proof_1: PlonkLinkProof,
}

/// A heap-allocated private settlement proof bundle
///
/// This type boxes the inner proof bundle to avoid large stack allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrivateSettlementProofBundle<Statement>(
    Box<PrivateSettlementProofBundleInner<Statement>>,
);

impl<Statement> PrivateSettlementProofBundle<Statement> {
    /// Create a new private settlement proof bundle from its components
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof: PlonkProof,
        statement: Statement,
        validity_link_proof_0: PlonkLinkProof,
        validity_link_proof_1: PlonkLinkProof,
        output_balance_link_proof_0: PlonkLinkProof,
        output_balance_link_proof_1: PlonkLinkProof,
    ) -> Self {
        Self(Box::new(PrivateSettlementProofBundleInner {
            proof,
            statement,
            validity_link_proof_0,
            validity_link_proof_1,
            output_balance_link_proof_0,
            output_balance_link_proof_1,
        }))
    }

    /// Create a new private settlement proof bundle from an inner type
    pub fn from_inner(inner: PrivateSettlementProofBundleInner<Statement>) -> Self {
        Self(Box::new(inner))
    }

    /// Consume the bundle and return the inner data
    pub fn into_inner(self) -> PrivateSettlementProofBundleInner<Statement> {
        *self.0
    }
}

impl<Statement> AsRef<PrivateSettlementProofBundleInner<Statement>>
    for PrivateSettlementProofBundle<Statement>
{
    fn as_ref(&self) -> &PrivateSettlementProofBundleInner<Statement> {
        &self.0
    }
}

impl<Statement> std::ops::Deref for PrivateSettlementProofBundle<Statement> {
    type Target = PrivateSettlementProofBundleInner<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ------------------------
// | Update Proof Bundles |
// ------------------------

/// A proof bundle for `VALID BALANCE CREATE`
pub type ValidBalanceCreateBundle = ProofBundle<ValidBalanceCreateStatement>;

/// A proof bundle for `VALID DEPOSIT`
pub type ValidDepositBundle = ProofBundle<ValidDepositStatement>;

/// A proof bundle for `VALID ORDER CANCELLATION`
pub type ValidOrderCancellationBundle = ProofBundle<ValidOrderCancellationStatement>;

/// A proof bundle for `VALID WITHDRAWAL`
pub type ValidWithdrawalBundle = ProofBundle<ValidWithdrawalStatement>;

// ----------------------------
// | Validity Circuit Bundles |
// ----------------------------

/// A proof bundle for `INTENT AND BALANCE VALIDITY`
pub type IntentAndBalanceValidityBundle = ProofAndHintBundle<IntentAndBalanceValidityStatement>;

/// A proof bundle for `INTENT AND BALANCE FIRST FILL VALIDITY`
pub type IntentAndBalanceFirstFillValidityBundle =
    ProofAndHintBundle<IntentAndBalanceFirstFillValidityStatement>;

/// A proof bundle for `INTENT ONLY VALIDITY`
pub type IntentOnlyValidityBundle = ProofAndHintBundle<IntentOnlyValidityStatement>;

/// A proof bundle for `INTENT ONLY FIRST FILL VALIDITY`
pub type IntentOnlyFirstFillValidityBundle =
    ProofAndHintBundle<IntentOnlyFirstFillValidityStatement>;

/// A proof bundle for `NEW OUTPUT BALANCE VALIDITY`
pub type NewOutputBalanceValidityBundle = ProofAndHintBundle<NewOutputBalanceValidityStatement>;

/// A proof bundle for `OUTPUT BALANCE VALIDITY`
pub type OutputBalanceValidityBundle = ProofAndHintBundle<OutputBalanceValidityStatement>;

// ------------------------------
// | Settlement Circuit Bundles |
// ------------------------------

/// A proof bundle for `INTENT AND BALANCE BOUNDED SETTLEMENT`
pub type IntentAndBalanceBoundedSettlementBundle =
    IntentOnlySettlementProofBundle<IntentAndBalanceBoundedSettlementStatement>;

/// A proof bundle for `INTENT AND BALANCE PRIVATE SETTLEMENT`
pub type IntentAndBalancePrivateSettlementBundle =
    PrivateSettlementProofBundle<IntentAndBalancePrivateSettlementStatement>;

/// A proof bundle for `INTENT AND BALANCE PUBLIC SETTLEMENT`
pub type IntentAndBalancePublicSettlementBundle =
    PublicSettlementProofBundle<IntentAndBalancePublicSettlementStatement>;

/// A proof bundle for `INTENT ONLY BOUNDED SETTLEMENT`
pub type IntentOnlyBoundedSettlementBundle =
    IntentOnlySettlementProofBundle<IntentOnlyBoundedSettlementStatement>;

/// A proof bundle for `INTENT ONLY PUBLIC SETTLEMENT`
pub type IntentOnlyPublicSettlementBundle =
    IntentOnlySettlementProofBundle<IntentOnlyPublicSettlementStatement>;

// -----------------------
// | Fee Circuit Bundles |
// -----------------------

/// A proof bundle for `VALID NOTE REDEMPTION`
pub type ValidNoteRedemptionBundle = ProofBundle<ValidNoteRedemptionStatement>;

/// A proof bundle for `VALID PRIVATE PROTOCOL FEE PAYMENT`
pub type ValidPrivateProtocolFeePaymentBundle =
    ProofBundle<ValidPrivateProtocolFeePaymentStatement>;

/// A proof bundle for `VALID PRIVATE RELAYER FEE PAYMENT`
pub type ValidPrivateRelayerFeePaymentBundle = ProofBundle<ValidPrivateRelayerFeePaymentStatement>;

/// A proof bundle for `VALID PUBLIC PROTOCOL FEE PAYMENT`
pub type ValidPublicProtocolFeePaymentBundle = ProofBundle<ValidPublicProtocolFeePaymentStatement>;

/// A proof bundle for `VALID PUBLIC RELAYER FEE PAYMENT`
pub type ValidPublicRelayerFeePaymentBundle = ProofBundle<ValidPublicRelayerFeePaymentStatement>;
