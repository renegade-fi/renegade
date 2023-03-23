//! Handles state sync and startup when the node first comes online

use circuits::{
    native_helpers::compute_poseidon_hash,
    zk_circuits::valid_commitments::{ValidCommitmentsStatement, ValidCommitmentsWitness},
    zk_gadgets::merkle::MerkleOpening,
    LinkableCommitment,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::biguint_to_scalar;
use std::thread::Builder as ThreadBuilder;
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::{mpsc::UnboundedSender, oneshot},
};
use tracing::log;

use crate::{
    error::CoordinatorError,
    gossip_api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    starknet_client::client::StarknetClient,
};

use super::{NetworkOrder, RelayerState};

/// An error emitted when order initialization fails
const ERR_STATE_INIT_FAILED: &str = "state initialization thread panic";
/// The name of the thread initialized to generate proofs of `VALID COMMITMENTS` at startup
const STATE_INIT_THREAD: &str = "state-init";

lazy_static! {}

impl RelayerState {
    /// Initialize the state by syncing and constructing indexes from on-chain and in
    /// network state
    ///
    /// This method does not block, instead it spawns a thread to manage the process of
    /// updating the order state. For this reason, the method is defined as a static
    /// method instead of an instance method, so that a lock need not be held on the
    /// state the entire time
    pub fn initialize(
        &self,
        starknet_client: StarknetClient,
        proof_manager_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) {
        // Spawn the helpers in a thread
        let self_clone = self.clone();
        ThreadBuilder::new()
            .name(STATE_INIT_THREAD.to_string())
            .spawn(move || {
                let runtime = RuntimeBuilder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    if let Err(e) = self_clone
                        .initialize_order_proof_helper(
                            starknet_client,
                            proof_manager_queue,
                            network_sender,
                        )
                        .await
                    {
                        log::error!("error initializing state: {e}")
                    }
                })
            })
            .expect(ERR_STATE_INIT_FAILED);
    }

    /// A helper passed as a callback to the threading logic in the caller
    async fn initialize_order_proof_helper(
        &self,
        starknet_client: StarknetClient,
        proof_manager_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) -> Result<(), CoordinatorError> {
        // Store a handle to the response channels for each proof; await them one by one
        let mut proof_response_channels = Vec::new();

        {
            // Iterate over all orders in all managed wallets and generate proofs
            let locked_wallet_index = self.read_wallet_index().await;
            for wallet in locked_wallet_index.get_all_wallets().await.into_iter() {
                // Build a Merkle authentication path for the wallet and attach it to the state
                let merkle_path = starknet_client
                    .find_merkle_authentication_path(wallet.get_commitment())
                    .await
                    .map_err(|err| CoordinatorError::StateInit(err.to_string()))?;

                // Index the wallet
                locked_wallet_index
                    .add_wallet_merkle_proof(&wallet.wallet_id, merkle_path.clone())
                    .await;

                log::info!(
                    "successfully recovered wallet {} authentication path from Starknet",
                    wallet.wallet_id
                );

                // Generate a merkle proof of inclusion for this wallet in the contract state
                let merkle_root = merkle_path.compute_root();
                let wallet_opening: MerkleOpening = merkle_path.into();

                let match_nullifier = wallet.get_match_nullifier();
                for (order_id, order) in wallet.orders.iter() {
                    // Add the order to the book
                    {
                        self.write_order_book()
                            .await
                            .add_order(NetworkOrder::new(
                                *order_id,
                                match_nullifier,
                                self.local_cluster_id.clone(),
                                true, /* local */
                            ))
                            .await;
                    } // order_book lock released

                    if let Some((_, balance, fee, fee_balance)) = locked_wallet_index
                        .get_order_balance_and_fee(&wallet.wallet_id, order_id)
                        .await
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
                        proof_manager_queue
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
                            self.read_order_book()
                                .await
                                .attach_validity_proof_witness(order_id, witness.clone())
                                .await;
                        } // order_book lock released
                    } else {
                        println!("Skipping wallet validity proof; no balance and fee found");
                        continue;
                    }
                }
            }
        } // locked_wallet_index released

        // Await a proof response for each order then attach it to the order index entry
        for (order_id, receiver) in proof_response_channels.into_iter() {
            // Await a proof
            let proof_bundle: ValidCommitmentsBundle = receiver.await.unwrap().into();

            // Update the local orderbook state
            self.add_order_validity_proof(&order_id, proof_bundle.clone())
                .await;

            // Gossip about the updated proof to the network
            let message = GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(
                    OrderBookManagementMessage::OrderProofUpdated {
                        order_id,
                        cluster: self.local_cluster_id.clone(),
                        proof: proof_bundle,
                    },
                ),
            };
            network_sender.send(message).unwrap()
        }

        Ok(())
    }
}
