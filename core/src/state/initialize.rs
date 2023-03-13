//! Handles state sync and startup when the node first comes online

use circuits::{
    native_helpers::compute_poseidon_hash, zk_circuits::valid_commitments::ValidCommitmentsWitness,
    zk_gadgets::merkle::MerkleOpening, LinkableCommitment,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{
    biguint_to_scalar, biguint_to_starknet_felt, scalar_to_biguint, starknet_felt_to_biguint,
    starknet_felt_to_scalar, starknet_felt_to_u64,
};
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use reqwest::Url;
use starknet::core::{types::FieldElement as StarknetFieldElement, utils::get_selector_from_name};
use starknet_providers::jsonrpc::{models::EventFilter, HttpTransport, JsonRpcClient};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    str::FromStr,
    thread::Builder as ThreadBuilder,
};
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
    error::CoordinatorError,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    MERKLE_HEIGHT,
};

use super::{
    wallet::{MerkleAuthenticationPath, Wallet},
    MerkleTreeCoords, NetworkOrder, RelayerState,
};

/// An error emitted when order initialization fails
const ERR_STATE_INIT_FAILED: &str = "state initialization thread panic";
/// The name of the thread initialized to generate proofs of `VALID COMMITMENTS` at startup
const STATE_INIT_THREAD: &str = "state-init";

lazy_static! {
    /// The event selector for internal node changes
    static ref INTERNAL_NODE_CHANGED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("Merkle_internal_node_changed").unwrap();
    /// The event selector for Merkle value insertion
    static ref VALUE_INSERTED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("Merkle_value_inserted").unwrap();
    /// The value of an empty leaf in the Merkle tree
    static ref EMPTY_LEAF_VALUE: Scalar = {
        let val_bigint = BigUint::from_str(
            "306932273398430716639340090025251549301604242969558673011416862133942957551"
        ).unwrap();
        biguint_to_scalar(&val_bigint)
    };
    /// The default values of an authentication path; i.e. the values in the path before any
    /// path elements are changed by insertions
    ///
    /// These values are simply recursive hashes of the empty leaf value, as this builds the
    /// empty tree
    static ref DEFAULT_AUTHENTICATION_PATH: [Scalar; MERKLE_HEIGHT] = {
        let mut values = Vec::with_capacity(MERKLE_HEIGHT);

        let curr_val = *EMPTY_LEAF_VALUE;
        for _ in 0..MERKLE_HEIGHT {
            values.push(compute_poseidon_hash(&[curr_val, curr_val]));
        }

        values.try_into().unwrap()
    };
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
    ) -> Result<(), CoordinatorError> {
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
                // Build a Merkle authentication path for the wallet and attach it to the state
                let merkle_path = self
                    .build_merkle_authentication_path(
                        &wallet,
                        contract_address.clone(),
                        &starknet_client,
                    )
                    .await?;

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
                            wallet_opening: wallet_opening.clone(),
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

        Ok(())
    }

    /// Searches on-chain state for the insertion of the given wallet, then finds the most
    /// recent updates of the path's siblings and creates a Merkle authentication path
    async fn build_merkle_authentication_path(
        &self,
        wallet: &Wallet,
        contract_address: String,
        starknet_client: &JsonRpcClient<HttpTransport>,
    ) -> Result<MerkleAuthenticationPath, CoordinatorError> {
        // Find the wallet in the commitment tree
        let leaf_index = self
            .find_wallet_in_merkle_tree(wallet, contract_address.clone(), starknet_client)
            .await?;

        // Construct a set that holds pairs of (depth, index) values in the authentication path; i.e. the
        // tree coordinates of the sibling nodes in the authentication path
        let mut sibling_tree_coords = HashSet::new();
        let mut curr_height_index = leaf_index.clone();
        for height in (1..MERKLE_HEIGHT + 1).rev() {
            // If the LSB of the node index at the current height is zero, the node
            // is a left hand child. If the LSB is one, it is a right hand child.
            // Choose the index of its sibling
            let sibling_index = if &curr_height_index % 2u8 == BigUint::from(0u8) {
                &curr_height_index + 1u8
            } else {
                &curr_height_index - 1u8
            };

            sibling_tree_coords.insert(MerkleTreeCoords::new(height, sibling_index));
            curr_height_index >>= 1;
        }

        // Search for the last time these values changed in the tree
        let path_values = self
            .scan_for_tree_coords(sibling_tree_coords, contract_address, starknet_client)
            .await?;

        // Order by height and return
        let mut path = *DEFAULT_AUTHENTICATION_PATH;
        for (coordinate, value) in path_values.into_iter() {
            let path_index = MERKLE_HEIGHT - coordinate.height;
            path[path_index] = starknet_felt_to_scalar(&value);
        }

        Ok(MerkleAuthenticationPath::new(
            path,
            leaf_index,
            wallet.get_commitment(),
        ))
    }

    /// Finds the commitment to the wallet in the Merkle tree and returns its
    /// leaf index
    async fn find_wallet_in_merkle_tree(
        &self,
        wallet: &Wallet,
        contract_address: String,
        starknet_client: &JsonRpcClient<HttpTransport>,
    ) -> Result<BigUint, CoordinatorError> {
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
                .get_events(
                    events_filter.clone(),
                    pagination_token,
                    100, /* chunk_size */
                )
                .await
                .unwrap();
            pagination_token = events_batch.continuation_token;

            for event in events_batch.events.iter() {
                let index = event.data[0];
                let value = event.data[1];

                if value == wallet_commit_mod {
                    return Ok(starknet_felt_to_biguint(&index));
                }
            }
        }

        log::info!("Failed to find wallet in commitment tree");
        Err(CoordinatorError::StateInit(
            "could not find wallet in commitment tree".to_string(),
        ))
    }

    /// Finds the last time the given tree coordinate pairs changed in the
    /// transaction history, and returns their most recent value
    #[allow(unused)]
    async fn scan_for_tree_coords(
        &self,
        coords: HashSet<MerkleTreeCoords>,
        contract_address: String,
        starknet_client: &JsonRpcClient<HttpTransport>,
    ) -> Result<HashMap<MerkleTreeCoords, StarknetFieldElement>, CoordinatorError> {
        // Build a filter to query events with
        let parsed_contract_address = StarknetFieldElement::from_str(&contract_address).unwrap();
        let filter = EventFilter {
            from_block: None,
            to_block: None,
            address: Some(parsed_contract_address),
            keys: Some(vec![*INTERNAL_NODE_CHANGED_EVENT_SELECTOR]),
        };

        // Loop over pages to find all the coords
        let mut pagination_token = Some("0".to_string());
        let mut result_map = HashMap::new();
        while pagination_token.is_some() {
            // Fetch the next page of events
            let events_page = starknet_client
                .get_events(filter.clone(), pagination_token, 100 /* chunk_size */)
                .await
                .map_err(|err| CoordinatorError::StateInit(err.to_string()))?;

            pagination_token = events_page.continuation_token;
            for event in events_page.events.into_iter() {
                let height: usize = starknet_felt_to_u64(&event.data[0]) as usize;
                let index = starknet_felt_to_biguint(&event.data[1]);
                let new_value = event.data[2];

                // If this is one of the coordinates requested, add it to the result
                let tree_coords = MerkleTreeCoords { height, index };
                if coords.contains(&tree_coords) {
                    result_map.insert(tree_coords, new_value);
                }
            }
        }

        Ok(result_map)
    }
}
