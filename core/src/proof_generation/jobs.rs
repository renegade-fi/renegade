//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process

use circuits::{
    types::{fee::Fee, keychain::KeyChain},
    zk_circuits::valid_wallet_create::{ValidWalletCreateCommitment, ValidWalletCreateStatement},
};
use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::r1cs::R1CSProof;
use tokio::sync::oneshot::Sender;

use crate::MAX_FEES;

// ----------------------
// | Proof Return Types |
// ----------------------

/// The response type for a request to generate a proof of `VALID WALLET CREATE`
#[derive(Clone, Debug)]
pub struct ValidWalletCreateBundle(
    pub ValidWalletCreateCommitment<MAX_FEES>,
    pub ValidWalletCreateStatement,
    pub R1CSProof,
);

/// The bundle returned by the proof generation module
#[derive(Clone, Debug)]
pub enum ProofBundle {
    /// A witness commitment, statement, and proof of `VALID WALLET CREATE`
    ValidWalletCreate(ValidWalletCreateBundle),
}

/// Unsafe cast implementations, will panic if type is incorrect
impl From<ProofBundle> for ValidWalletCreateBundle {
    fn from(bundle: ProofBundle) -> Self {
        #[allow(irrefutable_let_patterns)]
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
pub enum ProofJob {
    /// A request has come in to create a new wallet
    /// The proof generation module should generate a proof of
    /// `VALID WALLET CREATE`
    ValidWalletCreate {
        /// The fees to initialize the wallet with
        fees: Vec<Fee>,
        /// The keychain to use in the wallet
        keys: KeyChain,
        /// The wallet randomness to seed commitments and nullifiers with
        randomness: Scalar,
    },
}
