//! Helpers for common functionality across tasks

use std::sync::Arc;

use arbitrum_client::{client::ArbitrumClient, errors::ArbitrumClientError};
use circuit_types::{
    balance::Balance,
    native_helpers::{
        compute_wallet_private_share_commitment, create_wallet_shares_from_private, reblind_wallet,
        wallet_from_blinded_shares,
    },
    note::Note,
    order::Order,
    r#match::OrderSettlementIndices,
    SizedWallet,
};
use circuits::zk_circuits::{
    proof_linking::link_sized_commitments_reblind,
    valid_commitments::{
        SizedValidCommitmentsWitness, ValidCommitmentsStatement, ValidCommitmentsWitness,
    },
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement, ValidReblindWitness},
};
use common::types::{
    proof_bundles::ProofBundle,
    tasks::{PayOfflineFeeTaskDescriptor, RedeemRelayerFeeTaskDescriptor},
    wallet::{Wallet, WalletAuthenticationPath, WalletIdentifier},
};
use common::types::{
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};
use gossip_api::pubsub::{
    orderbook::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    PubsubMessage,
};
use job_types::{
    network_manager::{NetworkManagerJob, NetworkManagerQueue},
    proof_manager::{ProofJob, ProofManagerJob, ProofManagerQueue},
};
use num_bigint::BigUint;
use state::State;
use tokio::sync::oneshot::{self, Receiver as TokioReceiver};

// -------------
// | Constants |
// -------------

/// Error message emitted when enqueuing a job with the proof manager fails
const ERR_ENQUEUING_JOB: &str = "error enqueuing job with proof manager";
/// Error message emitted when a balance cannot be found for an order
const ERR_BALANCE_NOT_FOUND: &str = "cannot find balance for order";
/// Error message emitted when a wallet is given missing an authentication path
const ERR_MISSING_AUTHENTICATION_PATH: &str = "wallet missing authentication path";
/// Error message emitted when an order cannot be found in a wallet
const ERR_ORDER_NOT_FOUND: &str = "cannot find order in wallet";
/// Error message emitted when proving VALID COMMITMENTS fails
const ERR_PROVE_COMMITMENTS_FAILED: &str = "failed to prove valid commitments";
/// Error message emitted when proving VALID REBLIND fails
const ERR_PROVE_REBLIND_FAILED: &str = "failed to prove valid reblind";

// -----------
// | Helpers |
// -----------

/// Enqueue a job with the proof manager
///
/// Returns a channel on which the proof manager will send the response
pub(crate) fn enqueue_proof_job(
    job: ProofJob,
    work_queue: &ProofManagerQueue,
) -> Result<TokioReceiver<ProofBundle>, String> {
    let (response_sender, response_receiver) = oneshot::channel();
    work_queue
        .send(ProofManagerJob { type_: job, response_channel: response_sender })
        .map_err(|_| ERR_ENQUEUING_JOB.to_string())?;

    Ok(response_receiver)
}

/// Find the merkle authentication path of a wallet
pub(crate) async fn find_merkle_path(
    wallet: &Wallet,
    arbitrum_client: &ArbitrumClient,
) -> Result<WalletAuthenticationPath, ArbitrumClientError> {
    // The contract indexes the wallet by its commitment to the public and private
    // secret shares, find this in the Merkle tree
    arbitrum_client.find_merkle_authentication_path(wallet.get_wallet_share_commitment()).await
}

/// Re-blind the wallet and prove `VALID REBLIND` for the wallet
pub(crate) fn construct_wallet_reblind_proof(
    wallet: &Wallet,
    prover_queue: &ProofManagerQueue,
) -> Result<(SizedValidReblindWitness, TokioReceiver<ProofBundle>), String> {
    // If the wallet doesn't have an authentication path return an error
    let authentication_path =
        wallet.merkle_proof.clone().ok_or_else(|| ERR_MISSING_AUTHENTICATION_PATH.to_string())?;

    // Reblind the wallet
    let circuit_wallet: SizedWallet =
        wallet_from_blinded_shares(&wallet.private_shares, &wallet.blinded_public_shares);
    let (reblinded_private_shares, reblinded_public_shares) =
        reblind_wallet(&wallet.private_shares, &circuit_wallet);

    let merkle_root = authentication_path.compute_root();
    let private_reblinded_commitment =
        compute_wallet_private_share_commitment(&reblinded_private_shares);

    // Construct the witness and statement
    let statement = ValidReblindStatement {
        original_shares_nullifier: wallet.get_wallet_nullifier(),
        reblinded_private_share_commitment: private_reblinded_commitment,
        merkle_root,
    };
    let witness = ValidReblindWitness {
        original_wallet_private_shares: wallet.private_shares.clone(),
        original_wallet_public_shares: wallet.blinded_public_shares.clone(),
        reblinded_wallet_private_shares: reblinded_private_shares,
        reblinded_wallet_public_shares: reblinded_public_shares,
        original_share_opening: authentication_path.into(),
        sk_match: wallet.key_chain.secret_keys.sk_match,
    };

    // Forward a job to the proof manager
    let job = ProofJob::ValidReblind { witness: witness.clone(), statement };
    let recv = enqueue_proof_job(job, prover_queue)?;

    Ok((witness, recv))
}

/// Prove `VALID COMMITMENTS` for an order within a wallet
///
/// Returns a copy of the witness for indexing
pub(crate) fn construct_order_commitment_proof(
    order: Order,
    valid_reblind_witness: &SizedValidReblindWitness,
    proof_manager_work_queue: &ProofManagerQueue,
) -> Result<(SizedValidCommitmentsWitness, TokioReceiver<ProofBundle>), String> {
    // Build an augmented wallet
    let mut augmented_wallet: SizedWallet = wallet_from_blinded_shares(
        &valid_reblind_witness.reblinded_wallet_private_shares,
        &valid_reblind_witness.reblinded_wallet_public_shares,
    );

    // Find balances at which the local party will spend and receive their
    // respective sides of the match
    let (indices, balance_send, balance_receive) =
        find_balances_and_indices(&order, &mut augmented_wallet)?;

    // Create new augmented public secret shares
    let reblinded_private_blinder = valid_reblind_witness.reblinded_wallet_private_shares.blinder;
    let reblinded_public_blinder = valid_reblind_witness.reblinded_wallet_public_shares.blinder;
    let augmented_blinder = reblinded_private_blinder + reblinded_public_blinder;
    let (_, augmented_public_shares) = create_wallet_shares_from_private(
        &augmented_wallet,
        &valid_reblind_witness.reblinded_wallet_private_shares.clone(),
        augmented_blinder,
    );

    // Build the witness and statement
    let statement = ValidCommitmentsStatement { indices };
    let witness = ValidCommitmentsWitness {
        private_secret_shares: valid_reblind_witness.reblinded_wallet_private_shares.clone(),
        public_secret_shares: valid_reblind_witness.reblinded_wallet_public_shares.clone(),
        augmented_public_shares,
        order,
        balance_send,
        relayer_fee: augmented_wallet.match_fee,
        balance_receive,
    };

    // Dispatch a job to the proof manager to prove `VALID COMMITMENTS`
    let job = ProofJob::ValidCommitments { witness: witness.clone(), statement };
    let recv = enqueue_proof_job(job, proof_manager_work_queue)?;

    Ok((witness, recv))
}

/// Build the indices and fetch the balances for a given order
///
/// Returns the indices and the send and receive balances respectively for the
/// order
fn find_balances_and_indices(
    order: &Order,
    wallet: &mut SizedWallet,
) -> Result<(OrderSettlementIndices, Balance, Balance), String> {
    let send_mint = order.send_mint();
    let receive_mint = order.receive_mint();

    let (send_index, send_balance) =
        find_or_augment_balance(send_mint, wallet, false /* augment */)
            .ok_or_else(|| ERR_BALANCE_NOT_FOUND.to_string())?;
    let (receive_index, receive_balance) =
        find_or_augment_balance(receive_mint, wallet, true /* augment */)
            .ok_or_else(|| ERR_BALANCE_NOT_FOUND.to_string())?;

    // Find the order in the wallet
    let order_index = find_order(order, wallet).ok_or_else(|| ERR_ORDER_NOT_FOUND.to_string())?;

    Ok((
        OrderSettlementIndices {
            order: order_index,
            balance_send: send_index,
            balance_receive: receive_index,
        },
        send_balance,
        receive_balance,
    ))
}

/// Find a balance in the wallet
///
/// If the balance is not found and the `augment` flag is set, the method
/// will find an empty balance and add a zero'd balance in its place
///
/// Returns the index at which the balance was found or augmented, if possible
fn find_or_augment_balance(
    mint: &BigUint,
    wallet: &mut SizedWallet,
    augment: bool,
) -> Option<(usize, Balance)> {
    let index = wallet.balances.iter().enumerate().find(|(_ind, balance)| mint.eq(&balance.mint));
    match index {
        Some((index, balance)) => Some((index, balance.clone())),
        None => {
            if !augment {
                return None;
            }

            // Find an empty balance and augment it
            let empty_balance_ind = wallet
                .balances
                .iter()
                .enumerate()
                .find(|(_ind, balance)| balance.mint.eq(&BigUint::from(0u8)))
                .map(|(ind, _balance)| ind)?;

            wallet.balances[empty_balance_ind] = Balance::new_from_mint(mint.clone());
            Some((empty_balance_ind, wallet.balances[empty_balance_ind].clone()))
        },
    }
}

/// Find an order in the wallet, returns the index at which the order was found
fn find_order(order: &Order, wallet: &SizedWallet) -> Option<usize> {
    wallet.orders.iter().enumerate().find(|(_ind, o)| (*o).eq(order)).map(|(ind, _o)| ind)
}

/// Find a wallet on-chain, and update its validity proofs. That is, a proof of
/// `VALID REBLIND` for the wallet, and one proof of `VALID COMMITMENTS` for
/// each order in the wallet
pub(crate) async fn update_wallet_validity_proofs(
    wallet: &Wallet,
    proof_manager_work_queue: ProofManagerQueue,
    global_state: State,
    network_sender: NetworkManagerQueue,
) -> Result<(), String> {
    let matchable_orders = wallet.get_matchable_orders();
    if matchable_orders.is_empty() {
        return Ok(());
    }

    // Dispatch a proof of `VALID REBLIND` for the wallet
    let (reblind_witness, reblind_response_channel) =
        construct_wallet_reblind_proof(wallet, &proof_manager_work_queue)?;

    // For each order, construct a proof of `VALID COMMITMENTS`
    let mut commitments_instances = Vec::new();
    for (id, order) in matchable_orders.iter() {
        // Start a proof of `VALID COMMITMENTS`
        let (commitments_witness, response_channel) = construct_order_commitment_proof(
            order.clone(),
            &reblind_witness,
            &proof_manager_work_queue,
        )?;
        commitments_instances.push((*id, commitments_witness, response_channel));
    }

    // Await the proof of `VALID REBLIND`
    let reblind_proof: ProofBundle =
        reblind_response_channel.await.map_err(|_| ERR_PROVE_REBLIND_FAILED.to_string())?;

    // Await proofs of `VALID COMMITMENTS` for each order, store them in the state
    for (order_id, commitments_witness, receiver) in commitments_instances.into_iter() {
        // Await a proof
        let commitment_proof: ProofBundle =
            receiver.await.map_err(|_| ERR_PROVE_COMMITMENTS_FAILED.to_string())?;

        link_and_store_proofs(
            &order_id,
            &commitments_witness,
            &reblind_witness,
            &commitment_proof,
            &reblind_proof,
            &global_state,
            &network_sender,
        )
        .await?;
    }

    Ok(())
}

/// Attach a validity proof and witness to the locally managed state
///
/// The proof is gossipped to the network so that peers may verify the validity
/// bundle and schedule matches on the proven order
async fn link_and_store_proofs(
    order_id: &OrderIdentifier,
    commitments_witness: &SizedValidCommitmentsWitness,
    reblind_witness: &SizedValidReblindWitness,
    commitments_bundle: &ProofBundle,
    reblind_bundle: &ProofBundle,
    global_state: &State,
    network_sender: &NetworkManagerQueue,
) -> Result<(), String> {
    // Prove the link between the reblind and commitments proofs
    let reblind_link_hint = &reblind_bundle.link_hint;
    let comms_link_hint = &commitments_bundle.link_hint;
    let linking_proof = link_sized_commitments_reblind(reblind_link_hint, comms_link_hint)
        .map_err(|e| e.to_string())?;

    // Record the bundle in the global state
    let reblind_proof = reblind_bundle.proof.clone().into();
    let commitment_proof = commitments_bundle.proof.clone().into();
    let proof_bundle = OrderValidityProofBundle { reblind_proof, commitment_proof, linking_proof };

    let witness_bundle = OrderValidityWitnessBundle {
        reblind_witness: Arc::new(reblind_witness.clone()),
        commitment_witness: Arc::new(commitments_witness.clone()),
        commitment_linking_hint: Arc::new(comms_link_hint.clone()),
    };

    global_state
        .add_local_order_validity_bundle(*order_id, proof_bundle.clone(), witness_bundle)?
        .await?;

    // Gossip the updated proofs to the network
    let message = PubsubMessage::Orderbook(OrderBookManagementMessage::OrderProofUpdated {
        order_id: *order_id,
        cluster: global_state.get_cluster_id()?,
        proof_bundle,
    });

    let job = NetworkManagerJob::pubsub(ORDER_BOOK_TOPIC.to_string(), message);
    network_sender.send(job).map_err(|e| e.to_string())
}

/// Enqueue tasks to settle fees from a wallet
pub(crate) async fn enqueue_fee_settlement_tasks(
    wallet_id: WalletIdentifier,
    state: &State,
) -> Result<(), String> {
    // Read the wallet
    let wallet = state.get_wallet(&wallet_id)?.ok_or(format!("wallet {wallet_id} not found"))?;
    for (mint, balance) in wallet.balances.iter() {
        if balance.relayer_fee_balance > 0 {
            enqueue_relayer_fee_settlement_task(wallet_id, mint.clone(), state)?;
        }

        if balance.protocol_fee_balance > 0 {
            enqueue_protocol_fee_settlement_task(wallet_id, mint.clone(), state)?;
        }
    }

    Ok(())
}

/// Enqueue a job to settle a relayer fee
fn enqueue_relayer_fee_settlement_task(
    wallet_id: WalletIdentifier,
    mint: BigUint,
    state: &State,
) -> Result<(), String> {
    let descriptor =
        PayOfflineFeeTaskDescriptor::new_relayer_fee(wallet_id, mint).expect("infallible");
    state.append_task(descriptor.into()).map_err(|e| e.to_string()).map(|_| ())
}

/// Enqueue a job to settle a protocol fee
fn enqueue_protocol_fee_settlement_task(
    wallet_id: WalletIdentifier,
    mint: BigUint,
    state: &State,
) -> Result<(), String> {
    let descriptor =
        PayOfflineFeeTaskDescriptor::new_protocol_fee(wallet_id, mint).expect("infallible");
    state.append_task(descriptor.into()).map_err(|e| e.to_string()).map(|_| ())
}

/// Enqueue a job to redeem a relayer fee into the relayer's wallet
pub(crate) fn enqueue_relayer_redeem_job(note: Note, state: &State) -> Result<(), String> {
    let relayer_wallet_id = state.get_relayer_wallet_id()?.ok_or("relayer wallet not found")?;
    let descriptor =
        RedeemRelayerFeeTaskDescriptor::new(relayer_wallet_id, note).expect("infallible");

    state.append_task(descriptor.into()).map_err(|e| e.to_string()).map(|_| ())
}
