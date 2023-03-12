//! Handles state sync and startup when the node first comes online

use circuits::{
    native_helpers::compute_poseidon_hash,
    zk_circuits::valid_commitments::ValidCommitmentsWitness,
    zk_gadgets::merkle::{MerkleOpening, MerkleRoot},
    LinkableCommitment,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{
    biguint_to_scalar, biguint_to_starknet_felt, scalar_to_biguint, starknet_felt_to_biguint,
};
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use reqwest::Url;
use starknet::core::{types::FieldElement as StarknetFieldElement, utils::get_selector_from_name};
use starknet_providers::jsonrpc::{models::EventFilter, HttpTransport, JsonRpcClient};
use std::{str::FromStr, thread::Builder as ThreadBuilder};
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::{mpsc::UnboundedSender, oneshot},
};
use tracing::log;

use crate::{
    api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    MERKLE_HEIGHT,
};

use super::{wallet::Wallet, NetworkOrder, RelayerState};

/// An error emitted when order initialization fails
const ERR_STATE_INIT_FAILED: &str = "state initialization thread panic";
/// The name of the thread initialized to generate proofs of `VALID COMMITMENTS` at startup
const STATE_INIT_THREAD: &str = "state-init";

lazy_static! {
    /// The event selector for Merkle value insertion
    static ref VALUE_INSERTED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("Merkle_value_inserted").unwrap();
}

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
        contract_address: String,
        starknet_api_gateway: String,
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
                runtime.block_on(self_clone.initialize_order_proof_helper(
                    contract_address,
                    starknet_api_gateway,
                    proof_manager_queue,
                    network_sender,
                ))
            })
            .expect(ERR_STATE_INIT_FAILED);
    }

    /// A helper passed as a callback to the threading logic in the caller
    async fn initialize_order_proof_helper(
        &self,
        contract_address: String,
        starknet_api_gateway: String,
        proof_manager_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: UnboundedSender<GossipOutbound>,
    ) {
        // Build a starknet RPC client
        let starknet_client = JsonRpcClient::new(HttpTransport::new(
            Url::parse(&starknet_api_gateway).unwrap(),
        ));

        // Store a handle to the response channels for each proof; await them one by one
        let mut proof_response_channels = Vec::new();

        {
            // Iterate over all orders in all managed wallets and generate proofs
            let locked_wallet_index = self.read_wallet_index().await;
            for wallet in locked_wallet_index.get_all_wallets().await.into_iter() {
                // Find the wallet's Merkle insertion index
                let leaf_index = self
                    .find_wallet_in_merkle_tree(&wallet, contract_address.clone(), &starknet_client)
                    .await;
                if leaf_index.is_none() {
                    log::info!("Did not find wallet in transaction history");
                    continue;
                }
                let leaf_index = leaf_index.unwrap();
                log::info!("Found wallet at leaf index: {leaf_index}");

                let match_nullifier = wallet.get_match_nullifier();
                for (order_id, order) in wallet.orders.iter() {
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
                        // Generate a merkle proof of inclusion for this wallet in the contract state
                        let (merkle_root, wallet_opening) = Self::generate_merkle_proof(&wallet);

                        // Attach a copy of the witness to the locally managed state
                        // This witness is reference by match computations which compute linkable commitments
                        // to the order and balance; i.e. they commit with the same randomness
                        {
                            let randomness_hash =
                                compute_poseidon_hash(&[biguint_to_scalar(&wallet.randomness)]);
                            self.read_order_book()
                                .await
                                .attach_validity_proof_witness(
                                    order_id,
                                    ValidCommitmentsWitness {
                                        wallet: wallet.clone().into(),
                                        order: order.clone().into(),
                                        balance: balance.clone().into(),
                                        fee: fee.clone().into(),
                                        fee_balance: fee_balance.clone().into(),
                                        wallet_opening: wallet_opening.clone(),
                                        randomness_hash: LinkableCommitment::new(randomness_hash),
                                        sk_match: wallet.secret_keys.sk_match,
                                    },
                                )
                                .await;
                        } // order_book lock released

                        // Create a job and a response channel to get proofs back on
                        let job = ProofJob::ValidCommitments {
                            wallet: wallet.clone().into(),
                            wallet_opening,
                            order: order.clone(),
                            balance,
                            fee,
                            fee_balance,
                            sk_match: wallet.secret_keys.sk_match,
                            merkle_root,
                        };
                        let (response_sender, response_receiver) = oneshot::channel();

                        // Send a request to build a proof
                        proof_manager_queue
                            .send(ProofManagerJob {
                                type_: job,
                                response_channel: response_sender,
                            })
                            .unwrap();

                        // Store a handle to the response channel
                        proof_response_channels.push((*order_id, response_receiver));
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
    }

    /// Finds the commitment to the wallet in the Merkle tree and returns its
    /// leaf index
    async fn find_wallet_in_merkle_tree(
        &self,
        wallet: &Wallet,
        contract_address: String,
        starknet_client: &JsonRpcClient<HttpTransport>,
    ) -> Option<BigUint> {
        // TODO: Do this as a bigint instead of a scalar mod the starknet prime
        let wallet_commitment = scalar_to_biguint(&wallet.get_commitment());
        let starknet_mod = starknet_felt_to_biguint(&StarknetFieldElement::MAX) + 1u8;
        let wallet_commit_mod = biguint_to_starknet_felt(&(wallet_commitment % starknet_mod));

        let contract_addr = StarknetFieldElement::from_str(&contract_address).unwrap();
        let events_filter = EventFilter {
            from_block: None,
            to_block: None,
            address: Some(contract_addr),
            keys: Some(vec![*VALUE_INSERTED_EVENT_SELECTOR]),
        };

        let mut pagination_token = Some("0".to_string());
        while pagination_token.is_some() {
            let events_batch = starknet_client
                .get_events(events_filter.clone(), None, 100 /* chunk_size */)
                .await
                .unwrap();
            pagination_token = events_batch.continuation_token;

            for event in events_batch.events.iter() {
                let index = event.data[0];
                let value = event.data[1];

                if value == wallet_commit_mod {
                    return Some(starknet_felt_to_biguint(&index));
                }
            }
        }

        None
    }

    /// Generate a dummy Merkle proof for an order
    ///
    /// Returns a tuple of (dummy root, merkle opening)
    ///
    /// TODO: Replace this with a method that retrieves or has access to the on-chain Merkle state
    /// and creates a legitimate Merkle proof
    fn generate_merkle_proof(wallet: &Wallet) -> (MerkleRoot, MerkleOpening) {
        // For now, just assume the wallet is the zero'th entry in the tree, and
        // the rest of the tree is zeros
        let opening_elems = vec![Scalar::zero(); MERKLE_HEIGHT];
        let opening_indices = vec![Scalar::zero(); MERKLE_HEIGHT];

        // Compute the dummy root
        let mut curr_root = wallet.get_commitment();
        for sibling in opening_elems.iter() {
            curr_root = compute_poseidon_hash(&[curr_root, *sibling]);
        }

        (
            curr_root,
            MerkleOpening {
                elems: opening_elems,
                indices: opening_indices,
            },
        )
    }
}
