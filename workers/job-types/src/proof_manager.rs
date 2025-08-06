//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process
//!
//! See the whitepaper https://renegade.fi/whitepaper.pdf for a formal specification
//! of the types defined here

use circuit_types::ProofLinkingHint;
use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_fee_redemption::{SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness},
    valid_malleable_match_settle_atomic::{
        SizedValidMalleableMatchSettleAtomicStatement, SizedValidMalleableMatchSettleAtomicWitness,
    },
    valid_match_settle::{SizedValidMatchSettleStatement, SizedValidMatchSettleWitness},
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWitness,
    },
    valid_offline_fee_settlement::{
        SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness,
    },
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_relayer_fee_settlement::{
        SizedValidRelayerFeeSettlementStatement, SizedValidRelayerFeeSettlementWitness,
    },
    valid_wallet_create::{SizedValidWalletCreateStatement, SizedValidWalletCreateWitness},
    valid_wallet_update::{SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness},
};
use common::types::proof_bundles::ProofBundle;
use tokio::sync::oneshot::Sender;
use util::channels::{
    TracedCrossbeamReceiver, TracedCrossbeamSender, new_traced_crossbeam_channel,
};

/// The queue type for the proof manager
pub type ProofManagerQueue = TracedCrossbeamSender<ProofManagerJob>;
/// The receiver type for the proof manager
pub type ProofManagerReceiver = TracedCrossbeamReceiver<ProofManagerJob>;

/// Create a new proof manager queue and receiver
pub fn new_proof_manager_queue() -> (ProofManagerQueue, ProofManagerReceiver) {
    new_traced_crossbeam_channel()
}

// -------------
// | Job Types |
// -------------

/// Represents a job enqueued in the proof manager's work queue
#[derive(Debug)]
pub struct ProofManagerJob {
    /// The type of job being requested
    pub type_: ProofJob,
    /// The response channel to send the proof back along
    pub response_channel: Sender<ProofBundle>,
}

/// The job type and parameterization
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
pub enum ProofJob {
    /// A request has to create a new wallet
    /// The proof generation module should generate a proof of
    /// `VALID WALLET CREATE`
    ValidWalletCreate {
        /// The witness used to prove `VALID WALLET CREATE`
        witness: SizedValidWalletCreateWitness,
        /// The statement used to prove `VALID WALLET CREATE`
        statement: SizedValidWalletCreateStatement,
    },
    /// A request to create a proof of `VALID REBLIND` for a wallet. This is
    /// used to reblind a wallet so that it may be settled by a counterparty
    /// without leaking identifying information
    ValidReblind {
        /// The witness used in the proof of `VALID REBLIND`
        witness: SizedValidReblindWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// REBLIND`
        statement: ValidReblindStatement,
    },
    /// A request to create a proof of `VALID COMMITMENTS` for an order,
    /// balance, fee tuple. This will be matched against in the handshake
    /// process
    ValidCommitments {
        /// The witness to use in the proof of `VALID COMMITMENTS`
        witness: SizedValidCommitmentsWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// COMMITMENTS`
        statement: ValidCommitmentsStatement,
    },
    /// a request to create a proof of `VALID WALLET UPDATE` specifying a user
    /// generated change to the underlying wallet. This nullifies the old
    /// wallet and becomes a new entry in the commitment tree
    ValidWalletUpdate {
        /// The witness to the statement of `VALID WALLET UPDATE`
        witness: SizedValidWalletUpdateWitness,
        /// The statement (public variables) parameterizing the proof
        statement: SizedValidWalletUpdateStatement,
    },
    /// A request to create a proof of `VALID MATCH SETTLE` in a single prover
    /// context
    ValidMatchSettleSingleprover {
        /// The witness to the proof of `VALID MATCH SETTLE`
        witness: SizedValidMatchSettleWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// MATCH SETTLE`
        statement: SizedValidMatchSettleStatement,
        /// The proof link hint for the first party's proof of `VALID
        /// COMMITMENTS`
        commitment_link0: ProofLinkingHint,
        /// The proof link hint for the second party's proof of `VALID
        /// COMMITMENTS`
        commitment_link1: ProofLinkingHint,
    },
    /// A request to create a proof of `VALID MATCH SETTLE ATOMIC` describing an
    /// atomic match settlement between an internal and an external order
    ValidMatchSettleAtomic {
        /// The witness to the proof of `VALID MATCH SETTLE ATOMIC`
        witness: SizedValidMatchSettleAtomicWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// MATCH SETTLE ATOMIC`
        statement: SizedValidMatchSettleAtomicStatement,
        /// The proof link hint for the internal party's proof of `VALID
        /// COMMITMENTS`
        commitments_link: ProofLinkingHint,
    },
    /// A request to create a proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
    /// describing a malleable match settlement between an internal and an
    /// external order
    ValidMalleableMatchSettleAtomic {
        /// The witness to the proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
        witness: SizedValidMalleableMatchSettleAtomicWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// MALLEABLE MATCH SETTLE ATOMIC`
        statement: SizedValidMalleableMatchSettleAtomicStatement,
        /// The proof link hint for the internal party's proof of `VALID
        /// COMMITMENTS`
        commitments_link: ProofLinkingHint,
    },
    /// A request to create a proof of `VALID RELAYER FEE SETTLEMENT` in a
    /// single prover context
    ValidRelayerFeeSettlement {
        /// The witness to the proof of `VALID RELAYER FEE SETTLEMENT`
        witness: SizedValidRelayerFeeSettlementWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// RELAYER FEE SETTLEMENT`
        statement: SizedValidRelayerFeeSettlementStatement,
    },
    /// A request to create a proof of `VALID OFFLINE FEE SETTLEMENT` in a
    /// single prover context
    ValidOfflineFeeSettlement {
        /// The witness to the proof of `VALID OFFLINE FEE SETTLEMENT`
        witness: SizedValidOfflineFeeSettlementWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// OFFLINE FEE SETTLEMENT`
        statement: SizedValidOfflineFeeSettlementStatement,
    },
    /// A request to create a proof of `VALID FEE REDEMPTION` in a
    /// single prover context
    ValidFeeRedemption {
        /// The witness to the proof of `VALID FEE REDEMPTION`
        witness: SizedValidFeeRedemptionWitness,
        /// The statement (public variables) to use in the proof of `VALID
        /// FEE REDEMPTION`
        statement: SizedValidFeeRedemptionStatement,
    },
}
