//! Defines the task the local node runs at startup to find existing wallets in the contract
//! state and create validity proofs for them

use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::Arc,
};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;
use tracing::log;

use crate::{
    gossip_api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    proof_generation::{
        jobs::{ProofManagerJob, ValidCommitmentsBundle, ValidReblindBundle},
        OrderValidityProofBundle, OrderValidityWitnessBundle,
    },
    starknet_client::{client::StarknetClient, error::StarknetClientError},
    state::{
        wallet::{WalletAuthenticationPath, WalletIdentifier},
        NetworkOrder, RelayerState,
    },
};

use super::{
    driver::{StateWrapper, Task},
    helpers::{
        construct_wallet_commitment_proof, construct_wallet_reblind_proof, find_merkle_path,
    },
};

/// The displayable name of the task
const INITIALIZE_STATE_TASK_NAME: &str = "initialize-state";

// -------------------
// | Task Definition |
// -------------------

/// Defines the flow for initializing relayer-global state
pub struct InitializeStateTask {
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The wallet openings reconstructed from contract state
    pub wallet_openings: HashMap<WalletIdentifier, WalletAuthenticationPath>,
    /// A client to interact with Starknet
    pub starknet_client: StarknetClient,
    /// A sender to the proof manager's work queue
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A channel to forward messages onto the network
    pub network_sender: UnboundedSender<GossipOutbound>,
    /// The state of the task as it executes
    pub task_state: InitializeStateTaskState,
}

/// The state of the task as it is executing
#[derive(Debug, Clone, Serialize)]
pub enum InitializeStateTaskState {
    /// The task is awaiting execution
    Pending,
    /// The task is finding Merkle authentication paths for each wallet
    FindingMerkleOpening,
    /// The task is creating validity proofs for each order of each wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl Display for InitializeStateTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<InitializeStateTaskState> for StateWrapper {
    fn from(state: InitializeStateTaskState) -> Self {
        StateWrapper::InitializeState(state)
    }
}

/// The error type the task may throw
#[derive(Clone, Debug)]
pub enum InitializeStateTaskError {
    /// Error interacting with Starknet
    Starknet(String),
    /// Error proving `VALID REBLIND` for a wallet
    ProveValidReblind(String),
    /// Error proving `VALID COMMITMENTS` for a wallet
    ProveValidCommitments(String),
}

#[async_trait]
impl Task for InitializeStateTask {
    type State = InitializeStateTaskState;
    type Error = InitializeStateTaskError;

    fn completed(&self) -> bool {
        matches!(self.task_state, InitializeStateTaskState::Completed)
    }

    fn name(&self) -> String {
        INITIALIZE_STATE_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    async fn step(&mut self) -> Result<(), Self::Error> {
        match self.task_state {
            InitializeStateTaskState::Pending => {
                self.task_state = InitializeStateTaskState::FindingMerkleOpening;
            }
            InitializeStateTaskState::FindingMerkleOpening => {
                self.find_wallet_openings().await?;
                self.task_state = InitializeStateTaskState::CreatingValidityProofs;
            }
            InitializeStateTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = InitializeStateTaskState::Completed;
            }
            InitializeStateTaskState::Completed => {
                unreachable!("step called on completed task")
            }
        }

        Ok(())
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl InitializeStateTask {
    /// Constructor
    pub async fn new(
        global_state: RelayerState,
        starknet_client: StarknetClient,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) -> Self {
        // Add all orders in the initial state to the order book
        Self::add_initial_orders_to_book(global_state.clone()).await;

        Self {
            global_state,
            wallet_openings: HashMap::new(),
            starknet_client,
            proof_manager_work_queue,
            network_sender,
            task_state: InitializeStateTaskState::Pending,
        }
    }

    /// Add all the orders of the initial wallets to the book
    async fn add_initial_orders_to_book(global_state: RelayerState) {
        let local_cluster_id = global_state.local_cluster_id.clone();

        for wallet in global_state
            .read_wallet_index()
            .await
            .get_all_wallets()
            .await
            .into_iter()
        {
            let wallet_nullifier = wallet.get_wallet_nullifier();
            for order_id in wallet.orders.into_keys() {
                global_state
                    .add_order(NetworkOrder::new(
                        order_id,
                        wallet_nullifier,
                        local_cluster_id.clone(),
                        true, /* local */
                    ))
                    .await;
            }
        }
    }

    /// Find all the wallet openings in the global state
    async fn find_wallet_openings(&mut self) -> Result<(), InitializeStateTaskError> {
        for wallet in self
            .global_state
            .read_wallet_index()
            .await
            .get_all_wallets()
            .await
        {
            let res = find_merkle_path(&wallet, &self.starknet_client).await;
            if let Err(StarknetClientError::NotFound(_)) = res {
                log::error!(
                    "could not find wallet {} in contract state",
                    wallet.wallet_id
                );
                continue;
            }

            let authentication_path =
                res.map_err(|err| InitializeStateTaskError::Starknet(err.to_string()))?;

            // Update global state with authentication path
            self.global_state
                .read_wallet_index()
                .await
                .add_wallet_merkle_proof(&wallet.wallet_id, authentication_path)
                .await;
        }

        Ok(())
    }

    /// Prove `VALID COMMITMENTS` and `VALID REBLIND` for all orders in all the initial wallets
    async fn create_validity_proofs(&self) -> Result<(), InitializeStateTaskError> {
        let locked_wallet_index = self.global_state.read_wallet_index().await;

        let mut reblind_response_channels = Vec::new();
        let mut commitment_response_channels = Vec::new();
        for wallet in self
            .global_state
            .read_wallet_index()
            .await
            .get_all_wallets()
            .await
        {
            // Start a proof of `VALID REBLIND`
            let (reblind_witness, response_channel) =
                construct_wallet_reblind_proof(&wallet, self.proof_manager_work_queue.clone())
                    .map_err(InitializeStateTaskError::ProveValidReblind)?;

            let wallet_reblind_witness = Arc::new(reblind_witness);
            reblind_response_channels.push((wallet.wallet_id, response_channel));

            // Create a proof of `VALID COMMITMENTS` for each order
            for (order_id, order) in wallet.orders.iter().filter(|(_id, o)| !o.is_default()) {
                // Start a proof of `VALID COMMITMENTS`
                let (commitments_witness, response_channel) = construct_wallet_commitment_proof(
                    wallet.clone(),
                    order.clone(),
                    self.proof_manager_work_queue.clone(),
                )
                .map_err(InitializeStateTaskError::ProveValidCommitments)?;

                let order_commitment_witness = Arc::new(commitments_witness);

                // Attach a copy of the witness to the locally managed state
                // This witness is referenced by match computations which compute linkable commitments
                // to shared witness elements; i.e. they commit with the same randomness
                {
                    self.global_state
                        .read_order_book()
                        .await
                        .attach_validity_proof_witness(
                            order_id,
                            OrderValidityWitnessBundle {
                                reblind_witness: wallet_reblind_witness.clone(),
                                commitment_witness: order_commitment_witness.clone(),
                            },
                        )
                        .await;
                } // order_book lock released

                commitment_response_channels.push((*order_id, wallet.wallet_id, response_channel));
            }
        }
        drop(locked_wallet_index); // release lock

        // Await all wallet level reblind proofs
        let mut reblind_proofs = HashMap::new();
        for (wallet_id, receiver) in reblind_response_channels.into_iter() {
            let proof: ValidReblindBundle = receiver
                .await
                .map_err(|err| InitializeStateTaskError::ProveValidReblind(err.to_string()))?
                .into();
            reblind_proofs.insert(wallet_id, Arc::new(proof));
        }

        // Await a proof response for each order then attach it to the order index entry
        for (order_id, wallet_id, receiver) in commitment_response_channels.into_iter() {
            // Await a proof
            let proof_bundle: ValidCommitmentsBundle = receiver
                .await
                .map_err(|err| InitializeStateTaskError::ProveValidCommitments(err.to_string()))?
                .into();

            // Add proofs to the global state, the local node will gossip these around
            let reblind_proof = reblind_proofs.get(&wallet_id).unwrap().clone();
            let proof_bundle = OrderValidityProofBundle {
                commitment_proof: Arc::new(proof_bundle),
                reblind_proof,
            };
            self.global_state
                .add_order_validity_proofs(&order_id, proof_bundle.clone())
                .await;

            // Gossip about the updated proof to the network
            let message = GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(
                    OrderBookManagementMessage::OrderProofUpdated {
                        order_id,
                        cluster: self.global_state.local_cluster_id.clone(),
                        proof_bundle,
                    },
                ),
            };
            self.network_sender.send(message).unwrap()
        }

        Ok(())
    }
}
