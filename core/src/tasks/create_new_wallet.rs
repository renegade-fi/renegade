//! A task defining the flow to create a new wallet, at a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID NEW WALLETS` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from on-chain state
//!     5. Prove `VALID COMMITMENTS`

use std::fmt::{Display, Formatter, Result as FmtResult};

use crossbeam::channel::Sender as CrossbeamSender;
use crypto::{
    elgamal::{encrypt_scalar, ElGamalCiphertext},
    fields::{biguint_to_scalar, scalar_to_biguint},
};
use itertools::Itertools;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Wallet,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletCreateBundle},
    starknet_client::{client::StarknetClient, error::StarknetClientError},
    state::{
        wallet::{Wallet as StateWallet, WalletIdentifier},
        RelayerState,
    },
    SizedWallet,
};

/// The error type for the task
#[derive(Clone, Debug)]
pub enum NewWalletTaskError {
    /// Error interacting with the Starknet client
    Starknet(String),
    /// Error sending a message to another worker
    SendMessage(String),
}

impl Display for NewWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

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
        wallet_id: WalletIdentifier,
        wallet: Wallet,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        // When we cast to a state wallet, the identifier is erased, add
        // it from the request explicitly
        let mut wallet: StateWallet = wallet.into();
        wallet.wallet_id = wallet_id;

        Self {
            wallet,
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }

    /// Run the task to completion, provides a wrapper of error logging
    /// around the helper defined below
    pub async fn run(self) -> Result<(), NewWalletTaskError> {
        let res = self.run_helper().await;
        if let Err(e) = res.clone() {
            log::error!("error running new wallet task: {e}");
        } else {
            log::info!("successfully created new wallet");
        }

        res
    }

    /// A helper to run the task to completion
    async fn run_helper(self) -> Result<(), NewWalletTaskError> {
        log::info!("Beginning new wallet task execution");

        // Index the wallet in the global state
        self.global_state
            .add_wallets(vec![self.wallet.clone()])
            .await;

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
            .map_err(|err| NewWalletTaskError::SendMessage(err.to_string()))?;

        let proof_bundle = response_receiver.await.unwrap();

        // Submit the wallet on-chain
        self.submit_new_wallet(proof_bundle.into())
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

        // Find the updated Merkle path for the wallet
        let merkle_auth_path = self
            .starknet_client
            .find_merkle_authentication_path(self.wallet.get_commitment())
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

        // Add the authentication path to the wallet in the global state
        self.global_state
            .read_wallet_index()
            .await
            .add_wallet_merkle_proof(&self.wallet.wallet_id, merkle_auth_path)
            .await;

        Ok(())
    }

    /// Submits a proof and wallet commitment + encryption on-chain
    ///
    /// TODO: Add wallet encryptions as well
    async fn submit_new_wallet(
        &self,
        proof: ValidWalletCreateBundle,
    ) -> Result<(), StarknetClientError> {
        // Compute a commitment to the wallet and submit the bundle on-chain
        let wallet_commitment = self.wallet.get_commitment();
        let wallet_ciphertext = self.encrypt_wallet();

        let tx_hash = self
            .starknet_client
            .new_wallet(wallet_commitment, wallet_ciphertext, proof)
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

    /// Generate an unstructured encryption of the wallet
    ///
    /// We will add structure to this later, for now it is sufficient to blob the
    /// encryption
    fn encrypt_wallet(&self) -> Vec<ElGamalCiphertext> {
        let circuit_wallet_type: SizedWallet = self.wallet.clone().into();
        let pk_view = scalar_to_biguint(&self.wallet.public_keys.pk_view);
        let mut ciphertexts = Vec::new();

        // Encrypt the balances
        circuit_wallet_type.balances.iter().for_each(|balance| {
            ciphertexts.push(encrypt_scalar(biguint_to_scalar(&balance.mint), &pk_view));
            ciphertexts.push(encrypt_scalar(balance.amount.into(), &pk_view));
        });

        // Encrypt the orders
        circuit_wallet_type.orders.iter().for_each(|order| {
            ciphertexts.push(encrypt_scalar(
                biguint_to_scalar(&order.quote_mint),
                &pk_view,
            ));
            ciphertexts.push(encrypt_scalar(
                biguint_to_scalar(&order.base_mint),
                &pk_view,
            ));
            ciphertexts.push(encrypt_scalar(order.side.into(), &pk_view));
            ciphertexts.push(encrypt_scalar(order.price.into(), &pk_view));
            ciphertexts.push(encrypt_scalar(order.amount.into(), &pk_view));
            ciphertexts.push(encrypt_scalar(order.timestamp.into(), &pk_view));
        });

        // Encrypt the fees
        circuit_wallet_type.fees.iter().for_each(|fee| {
            ciphertexts.push(encrypt_scalar(biguint_to_scalar(&fee.settle_key), &pk_view));
            ciphertexts.push(encrypt_scalar(biguint_to_scalar(&fee.gas_addr), &pk_view));
            ciphertexts.push(encrypt_scalar(fee.gas_token_amount.into(), &pk_view));
            ciphertexts.push(encrypt_scalar(fee.percentage_fee.into(), &pk_view));
        });

        // Encrypt the wallet randomness
        ciphertexts.push(encrypt_scalar(
            biguint_to_scalar(&self.wallet.randomness),
            &pk_view,
        ));

        // Remove the randomness used in each encryption, cleaner this way than
        // indexing into the tuple struct in all of the above
        ciphertexts
            .into_iter()
            .map(|(cipher, _)| cipher)
            .collect_vec()
    }
}
