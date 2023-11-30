//! Defines a task that looks up a wallet in contract storage by its
//! public view key identifier, then begins managing the wallet

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{atomic::AtomicBool, Arc},
};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{traits::BaseType, SizedWalletShare};
use common::types::wallet::{KeyChain, Wallet, WalletIdentifier, WalletMetadata};
use constants::Scalar;
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::gossip::GossipOutbound;
use itertools::Itertools;
use job_types::proof_manager::ProofManagerJob;
use renegade_crypto::hash::PoseidonCSPRNG;
use serde::Serialize;
use state::RelayerState;
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tracing::log;
use uuid::Uuid;

use super::{
    driver::{StateWrapper, Task},
    helpers::{find_merkle_path, update_wallet_validity_proofs},
};

/// The error thrown when the wallet cannot be found in tx history
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in wallet_last_updated map";
/// The task name for the lookup wallet task
const LOOKUP_WALLET_TASK_NAME: &str = "lookup-wallet";

/// Represents a task to lookup a wallet in contract storage
pub struct LookupWalletTask {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The CSPRNG seed for the blinder stream
    pub blinder_seed: Scalar,
    /// The CSPRNG seed for the secret share stream
    pub secret_share_seed: Scalar,
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
    /// The wallet recovered from contract state
    pub wallet: Option<Wallet>,
    /// An arbitrum client for the task to submit transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task's execution
    pub task_state: LookupWalletTaskState,
}

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize)]
pub enum LookupWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl Display for LookupWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<LookupWalletTaskState> for StateWrapper {
    fn from(state: LookupWalletTaskState) -> Self {
        StateWrapper::LookupWallet(state)
    }
}

/// The error type thrown by the wallet lookup task
#[derive(Clone, Debug)]
pub enum LookupWalletTaskError {
    /// Wallet was not found in contract storage
    NotFound(String),
    /// Error generating a proof of `VALID COMMITMENTS`
    ProofGeneration(String),
    /// Error interacting with the arbitrum client
    Arbitrum(String),
}

impl Display for LookupWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for LookupWalletTaskError {}

#[async_trait]
impl Task for LookupWalletTask {
    type State = LookupWalletTaskState;
    type Error = LookupWalletTaskError;

    fn completed(&self) -> bool {
        matches!(self.state(), LookupWalletTaskState::Completed)
    }

    fn name(&self) -> String {
        LOOKUP_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            LookupWalletTaskState::Pending => {
                self.task_state = LookupWalletTaskState::FindingWallet
            },

            LookupWalletTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = LookupWalletTaskState::CreatingValidityProofs;
            },

            LookupWalletTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = LookupWalletTaskState::Completed;
            },

            LookupWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl LookupWalletTask {
    /// Constructor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: WalletIdentifier,
        blinder_stream_seed: Scalar,
        secret_share_stream_seed: Scalar,
        key_chain: KeyChain,
        arbitrum_client: ArbitrumClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            wallet_id,
            blinder_seed: blinder_stream_seed,
            secret_share_seed: secret_share_stream_seed,
            key_chain,
            wallet: None, // replaced in the first task step
            arbitrum_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_state: LookupWalletTaskState::Pending,
        }
    }

    // --------------
    // | Task Steps |
    // --------------

    /// Find the wallet in the contract storage and create an opening for the
    /// wallet
    async fn find_wallet(&mut self) -> Result<(), LookupWalletTaskError> {
        // Lookup the public and private shares from contract calldata
        let (blinded_public_shares, private_shares) = self.find_wallet_shares().await?;

        let blinder = blinded_public_shares.blinder + private_shares.blinder;
        let unblinded_public_shares = blinded_public_shares.unblind_shares(blinder);
        let recovered_wallet = unblinded_public_shares + private_shares.clone();

        // Construct a wallet from the recovered shares
        let mut wallet = Wallet {
            wallet_id: self.wallet_id,
            orders: recovered_wallet.orders.iter().cloned().map(|o| (Uuid::new_v4(), o)).collect(),
            balances: recovered_wallet
                .balances
                .iter()
                .cloned()
                .map(|b| (b.mint.clone(), b))
                .collect(),
            fees: recovered_wallet.fees.to_vec(),
            key_chain: KeyChain {
                public_keys: recovered_wallet.keys,
                secret_keys: self.key_chain.secret_keys.clone(),
            },
            blinder: recovered_wallet.blinder,
            metadata: WalletMetadata::default(),
            private_shares,
            blinded_public_shares,
            merkle_proof: None, // constructed below
            update_locked: Arc::new(AtomicBool::default()),
        };

        // Find the authentication path for the wallet
        let authentication_path = find_merkle_path(&wallet, &self.arbitrum_client)
            .await
            .map_err(|e| LookupWalletTaskError::Arbitrum(e.to_string()))?;
        wallet.merkle_proof = Some(authentication_path);

        self.global_state.update_wallet(wallet.clone()).await;
        self.wallet = Some(wallet);

        Ok(())
    }

    /// Prove `VALID REBLIND` for the recovered wallet, and `VALID COMMITMENTS`
    /// for each order within the wallet
    async fn create_validity_proofs(&self) -> Result<(), LookupWalletTaskError> {
        let wallet = self
            .wallet
            .clone()
            .expect("wallet should be present when CreateValidityProofs state is reached");

        update_wallet_validity_proofs(
            &wallet,
            self.proof_manager_work_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(LookupWalletTaskError::ProofGeneration)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Find the public and private shares of the wallet seeded by the given
    /// value
    ///
    /// Unblinds the public shares before returning them
    async fn find_wallet_shares(
        &self,
    ) -> Result<(SizedWalletShare, SizedWalletShare), LookupWalletTaskError> {
        // Find the latest index of the wallet in its share stream
        let (blinder_index, curr_blinder, curr_blinder_private_share) =
            self.find_latest_wallet_tx().await?;

        // Fetch the secret shares from the tx
        let blinder_public_share = curr_blinder - curr_blinder_private_share;
        let blinded_public_shares = self
            .arbitrum_client
            .fetch_public_shares_from_tx(blinder_public_share)
            .await
            .map_err(|e| LookupWalletTaskError::Arbitrum(e.to_string()))?;

        // Build an iterator over private secret shares and fast forward to the given
        // wallet index.
        //
        // `shares_per_wallet` does not include the private share of the wallet blinder,
        // this comes from a separate stream of randomness, so we take the serialized
        // length minus one
        let shares_per_wallet = blinded_public_shares.to_scalars().len();
        let mut private_share_csprng = PoseidonCSPRNG::new(self.secret_share_seed);
        private_share_csprng.advance_by((blinder_index - 1) * (shares_per_wallet - 1)).unwrap();

        // Sample private secret shares for the wallet
        let mut new_private_shares = private_share_csprng.take(shares_per_wallet);
        let mut private_shares = SizedWalletShare::from_scalars(&mut new_private_shares);
        private_shares.blinder = curr_blinder_private_share;

        Ok((blinded_public_shares, private_shares))
    }

    /// Find the latest update of a wallet that has been submitted to the
    /// contract. The update is represented as an index into the blinder stream
    ///
    /// Returns a tuple: `(blinder_index, blinder, blinder_private_share)`
    async fn find_latest_wallet_tx(
        &self,
    ) -> Result<(usize, Scalar, Scalar), LookupWalletTaskError> {
        // Find the latest transaction updating the wallet, as indexed by the public
        // share of the blinders
        let mut blinder_csprng = PoseidonCSPRNG::new(self.blinder_seed);

        let mut blinder_index = 0;
        let mut curr_blinder = Scalar::zero();
        let mut curr_blinder_private_share = Scalar::zero();

        let mut updating_tx = None;

        while
            let (blinder, private_share) = blinder_csprng.next_tuple().unwrap() &&
            let Some(tx) = self
                .arbitrum_client
                .get_public_blinder_tx(blinder - private_share)
                .await
                .map_err(|e| LookupWalletTaskError::Arbitrum(e.to_string()))?
        {
            updating_tx = Some(tx);

            curr_blinder = blinder;
            curr_blinder_private_share = private_share;
            blinder_index += 1;
        }

        let latest_tx = updating_tx
            .ok_or_else(|| LookupWalletTaskError::NotFound(ERR_WALLET_NOT_FOUND.to_string()))?;
        log::info!("latest updating tx: {:#x}", latest_tx);

        Ok((blinder_index, curr_blinder, curr_blinder_private_share))
    }
}
