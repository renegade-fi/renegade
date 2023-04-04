//! Defines the task the local node runs at startup to find existing wallets in the contract
//! state and create validity proofs for them

use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use circuits::{
    native_helpers::compute_poseidon_hash,
    zk_circuits::valid_commitments::{ValidCommitmentsStatement, ValidCommitmentsWitness},
    zk_gadgets::merkle::MerkleOpening,
    LinkableCommitment,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::biguint_to_scalar;
use serde::Serialize;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tracing::log;

use crate::{
    gossip_api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    starknet_client::{client::StarknetClient, error::StarknetClientError},
    state::{
        wallet::{MerkleAuthenticationPath, WalletIdentifier},
        NetworkOrder, RelayerState,
    },
};

use super::driver::{StateWrapper, Task};

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
    pub wallet_openings: HashMap<WalletIdentifier, MerkleAuthenticationPath>,
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
    pub fn new(
        global_state: RelayerState,
        starknet_client: StarknetClient,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) -> Self {
        Self {
            global_state,
            wallet_openings: HashMap::new(),
            starknet_client,
            proof_manager_work_queue,
            network_sender,
            task_state: InitializeStateTaskState::Pending,
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
            let commitment = wallet.get_commitment();
            let res = self
                .starknet_client
                .find_merkle_authentication_path(commitment)
                .await;

            if let Err(StarknetClientError::NotFound(_)) = res {
                log::error!(
                    "could not find wallet {} in contract state",
                    wallet.wallet_id
                );
                continue;
            }

            let authentication_path =
                res.map_err(|err| InitializeStateTaskError::Starknet(err.to_string()))?;
            self.wallet_openings
                .insert(wallet.wallet_id, authentication_path);
        }

        Ok(())
    }

    /// Prove `VALID COMMITMENTS` for all orders in all the initial wallets
    async fn create_validity_proofs(&self) -> Result<(), InitializeStateTaskError> {
        // Generate a merkle proof of inclusion for this wallet in the contract state
        let mut proof_response_channels = Vec::new();
        let locked_wallet_index = self.global_state.read_wallet_index().await;

        for (ref wallet_id, merkle_path) in self.wallet_openings.clone().into_iter() {
            let wallet = locked_wallet_index.get_wallet(wallet_id).await.unwrap();
            let merkle_root = merkle_path.compute_root();
            let wallet_opening: MerkleOpening = merkle_path.into();

            let match_nullifier = wallet.get_match_nullifier();
            for (order_id, order) in wallet.orders.iter() {
                // Add the order to the book
                {
                    self.global_state
                        .add_order(NetworkOrder::new(
                            *order_id,
                            match_nullifier,
                            self.global_state.local_cluster_id.clone(),
                            true, /* local */
                        ))
                        .await;
                } // order_book lock released

                if let Some((balance, fee, fee_balance)) =
                    wallet.get_balance_and_fee_for_order(order)
                {
                    // Construct the witness and statement to generate a commitments proof from
                    let randomness_hash =
                        compute_poseidon_hash(&[biguint_to_scalar(&wallet.randomness)]);
                    let witness = ValidCommitmentsWitness {
                        wallet: wallet.clone().into(),
                        order: order.clone().into(),
                        balance: balance.clone().into(),
                        fee: fee.clone().into(),
                        fee_balance: fee_balance.clone().into(),
                        wallet_opening: wallet_opening.clone(),
                        randomness_hash: LinkableCommitment::new(randomness_hash),
                        sk_match: wallet.secret_keys.sk_match,
                    };

                    let statement = ValidCommitmentsStatement {
                        nullifier: match_nullifier,
                        merkle_root,
                        pk_settle: wallet.public_keys.pk_settle,
                    };

                    // Create a job and a response channel to get proofs back on, and forward the job
                    let (response_sender, response_receiver) = oneshot::channel();
                    self.proof_manager_work_queue
                        .send(ProofManagerJob {
                            type_: ProofJob::ValidCommitments {
                                witness: witness.clone(),
                                statement,
                            },
                            response_channel: response_sender,
                        })
                        .unwrap();

                    // Store a handle to the response channel
                    proof_response_channels.push((*order_id, response_receiver));

                    // Attach a copy of the witness to the locally managed state
                    // This witness is reference by match computations which compute linkable commitments
                    // to the order and balance; i.e. they commit with the same randomness
                    {
                        self.global_state
                            .read_order_book()
                            .await
                            .attach_validity_proof_witness(order_id, witness.clone())
                            .await;
                    } // order_book lock released
                } else {
                    log::error!("Skipping wallet validity proof; no balance and fee found");
                    continue;
                }
            }
        }
        drop(locked_wallet_index); // release lock

        // Await a proof response for each order then attach it to the order index entry
        for (order_id, receiver) in proof_response_channels.into_iter() {
            // Await a proof
            let proof_bundle: ValidCommitmentsBundle = receiver.await.unwrap().into();

            // Update the local orderbook state
            self.global_state
                .add_order_validity_proof(&order_id, proof_bundle.clone())
                .await;

            // Gossip about the updated proof to the network
            let message = GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(
                    OrderBookManagementMessage::OrderProofUpdated {
                        order_id,
                        cluster: self.global_state.local_cluster_id.clone(),
                        proof: proof_bundle,
                    },
                ),
            };
            self.network_sender.send(message).unwrap()
        }
        Ok(())
    }
}
