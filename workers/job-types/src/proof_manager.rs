//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process
//!
//! See the whitepaper https://renegade.fi/whitepaper.pdf for a formal specification
//! of the types defined here

use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_match_settle::{SizedValidMatchSettleStatement, SizedValidMatchSettleWitness},
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_wallet_create::{SizedValidWalletCreateStatement, SizedValidWalletCreateWitness},
    valid_wallet_update::{SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness},
};
use common::types::proof_bundles::ProofBundle;
use crossbeam::channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use tokio::sync::oneshot::Sender;

/// The queue type for the proof manager
pub type ProofManagerQueue = CrossbeamSender<ProofManagerJob>;
/// The receiver type for the proof manager
pub type ProofManagerReceiver = CrossbeamReceiver<ProofManagerJob>;

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
    },
}
