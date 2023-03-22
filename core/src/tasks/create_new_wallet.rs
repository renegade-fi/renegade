//! A task defining the flow to create a new wallet, at a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID NEW WALLETS` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from on-chain state
//!     5. Prove `VALID COMMITMENTS`

use circuits::types::keychain::KeyChain as CircuitKeyChain;
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::biguint_to_scalar;
use itertools::Itertools;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Wallet,
    proof_generation::jobs::{ProofJob, ProofManagerJob},
    state::RelayerState,
};

/// The task struct defining the long-run async flow for creating a new wallet
pub struct NewWalletTask {
    /// The wallet to create
    pub wallet: Wallet,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl NewWalletTask {
    /// Constructor
    pub fn new(
        wallet: Wallet,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            wallet,
            global_state,
            proof_manager_work_queue,
        }
    }

    /// Run the task to completion
    pub async fn run(self) {
        log::info!("Beginning new wallet task execution");

        // Convert API types to circuit specific types
        let fees = self
            .wallet
            .fees
            .clone()
            .into_iter()
            .map(|fee| fee.into())
            .collect_vec();

        let keys = CircuitKeyChain {
            pk_root: biguint_to_scalar(&self.wallet.key_chain.public_keys.pk_root),
            pk_match: biguint_to_scalar(&self.wallet.key_chain.public_keys.pk_match),
            pk_settle: biguint_to_scalar(&self.wallet.key_chain.public_keys.pk_settle),
            pk_view: biguint_to_scalar(&self.wallet.key_chain.public_keys.pk_view),
        };

        // Enqueue a job with the proof manager to prove `VALID NEW WALLET`
        let (response_sender, response_receiver) = oneshot::channel();
        let job_req = ProofManagerJob {
            type_: ProofJob::ValidWalletCreate {
                fees,
                keys,
                randomness: biguint_to_scalar(&self.wallet.randomness),
            },
            response_channel: response_sender,
        };
        self.proof_manager_work_queue
            .send(job_req)
            .expect("error enqueuing proof manager job");

        let _proof_bundle = response_receiver.await;
        log::info!("got proof bundle for new wallet");
    }
}
