//! A task defining the flow to create a new wallet, at a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID NEW WALLETS` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from on-chain state
//!     5. Prove `VALID COMMITMENTS`

use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::biguint_to_scalar;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Wallet,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletCreateBundle},
    starknet_client::client::{AccountErr, StarknetClient},
    state::{wallet::Wallet as StateWallet, RelayerState},
};

/// The task struct defining the long-run async flow for creating a new wallet
pub struct NewWalletTask {
    /// The wallet to create
    pub wallet: StateWallet,
    /// A starknet client for the task to submit transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl NewWalletTask {
    /// Constructor
    pub fn new(
        wallet: Wallet,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            wallet: wallet.into(),
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }

    /// Run the task to completion
    pub async fn run(self) {
        log::info!("Beginning new wallet task execution");

        // Enqueue a job with the proof manager to prove `VALID NEW WALLET`
        let (response_sender, response_receiver) = oneshot::channel();
        let job_req = ProofManagerJob {
            type_: ProofJob::ValidWalletCreate {
                fees: self.wallet.fees.clone(),
                keys: self.wallet.public_keys,
                randomness: biguint_to_scalar(&self.wallet.randomness),
            },
            response_channel: response_sender,
        };
        self.proof_manager_work_queue
            .send(job_req)
            .expect("error enqueuing proof manager job");

        let proof_bundle = response_receiver.await.unwrap();
        log::info!("got proof bundle for new wallet");

        // Submit the wallet on-chain
        if let Err(e) = self.submit_new_wallet(proof_bundle.into()).await {
            log::error!("error submitting new wallet on-chain: {e}");
        };

        // Find the updated Merkle path for the wallet
        let merkle_auth_path = self
            .starknet_client
            .find_merkle_authentication_path(self.wallet.get_commitment())
            .await;
        match merkle_auth_path {
            Ok(auth_path) => {
                log::info!("found wallet at merkle index: {:?}", auth_path.leaf_index);
            }
            Err(e) => {
                log::error!("error finding merkle index: {e}")
            }
        }

        log::info!("submitted wallet on-chain")
    }

    /// Submits a proof and wallet commitment + encryption on-chain
    ///
    /// TODO: Add wallet encryptions as well
    async fn submit_new_wallet(&self, proof: ValidWalletCreateBundle) -> Result<(), AccountErr> {
        // Compute a commitment to the wallet and submit the bundle on-chain
        let wallet_commitment = self.wallet.get_commitment();
        let tx_hash = self
            .starknet_client
            .new_wallet(wallet_commitment, proof)
            .await?;

        let res = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await;

        if let Err(e) = res {
            log::error!("error polling tx: {e:?}");
        } else {
            log::info!(
                "transaction complete for wallet, status: {:?}",
                res.unwrap().status
            );
        }

        Ok(())
    }
}
