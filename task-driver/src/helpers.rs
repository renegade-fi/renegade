//! Helpers for common functionality across tasks

use arbitrum_client::{client::ArbitrumClient, errors::ArbitrumClientError};
use circuit_types::{
    balance::Balance,
    fee::Fee,
    native_helpers::{
        compute_wallet_private_share_commitment, create_wallet_shares_from_private, reblind_wallet,
        wallet_from_blinded_shares,
    },
    order::{Order, OrderSide},
    r#match::OrderSettlementIndices,
    SizedWallet,
};
use circuits::zk_circuits::{
    valid_commitments::{
        SizedValidCommitmentsWitness, ValidCommitmentsStatement, ValidCommitmentsWitness,
    },
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement, ValidReblindWitness},
};
use common::types::proof_bundles::{
    OrderValidityProofBundle, OrderValidityWitnessBundle, ValidCommitmentsBundle,
    ValidReblindBundle,
};
use common::types::{
    proof_bundles::ProofBundle,
    wallet::{Wallet, WalletAuthenticationPath},
};
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::{
    gossip::{GossipOutbound, PubsubMessage},
    orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use num_bigint::BigUint;
use state::RelayerState;
use tokio::sync::{
    mpsc::UnboundedSender as TokioSender,
    oneshot::{self, Receiver as TokioReceiver},
};

// -------------
// | Constants |
// -------------

/// Error message emitted when enqueuing a job with the proof manager fails
const ERR_ENQUEUING_JOB: &str = "error enqueuing job with proof manager";
/// Error message emitted when a balance cannot be found for an order
const ERR_BALANCE_NOT_FOUND: &str = "cannot find balance for order";
/// Error message emitted when a wallet is given missing an authentication path
const ERR_MISSING_AUTHENTICATION_PATH: &str = "wallet missing authentication path";
/// Error message emitted when a fee cannot be found for the wallet
const ERR_FEE_NOT_FOUND: &str = "fee not found in wallet";
/// Error message emitted when an order cannot be found in a wallet
const ERR_ORDER_NOT_FOUND: &str = "cannot find order in wallet";
/// Error message emitted when proving VALID COMMITMENTS fails
const ERR_PROVE_COMMITMENTS_FAILED: &str = "failed to prove valid commitments";
/// Error message emitted when proving VALID REBLIND fails
const ERR_PROVE_REBLIND_FAILED: &str = "failed to prove valid reblind";

// -----------
// | Helpers |
// -----------

/// Find the merkle authentication path of a wallet
pub(super) async fn find_merkle_path(
    wallet: &Wallet,
    arbitrum_client: &ArbitrumClient,
) -> Result<WalletAuthenticationPath, ArbitrumClientError> {
    // The contract indexes the wallet by its commitment to the public and private
    // secret shares, find this in the Merkle tree
    arbitrum_client.find_merkle_authentication_path(wallet.get_wallet_share_commitment()).await
}

/// Re-blind the wallet and prove `VALID REBLIND` for the wallet
pub(super) fn construct_wallet_reblind_proof(
    wallet: &Wallet,
    proof_manager_work_queue: &CrossbeamSender<ProofManagerJob>,
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
    let (proof_sender, proof_receiver) = oneshot::channel();
    proof_manager_work_queue
        .send(ProofManagerJob {
            type_: ProofJob::ValidReblind { witness: witness.clone(), statement },
            response_channel: proof_sender,
        })
        .map_err(|_| ERR_ENQUEUING_JOB.to_string())?;

    Ok((witness, proof_receiver))
}

/// Prove `VALID COMMITMENTS` for an order within a wallet
///
/// Returns a copy of the witness for indexing
pub(super) fn construct_wallet_commitment_proof(
    wallet: &Wallet,
    order: Order,
    valid_reblind_witness: &SizedValidReblindWitness,
    proof_manager_work_queue: &CrossbeamSender<ProofManagerJob>,
    disable_fee_validation: bool,
) -> Result<(SizedValidCommitmentsWitness, TokioReceiver<ProofBundle>), String> {
    // Choose the first fee. If no fee is found and fee validation is disabled, use
    // a zero fee
    let first_fee = wallet.fees.iter().find(|f| !f.is_default()).cloned();
    let fee = if disable_fee_validation {
        first_fee.unwrap_or(Fee::default())
    } else {
        first_fee.ok_or_else(|| ERR_FEE_NOT_FOUND.to_string())?
    };

    // Build an augmented wallet and find balances to update
    let mut augmented_wallet: SizedWallet = wallet_from_blinded_shares(
        &valid_reblind_witness.reblinded_wallet_private_shares,
        &valid_reblind_witness.reblinded_wallet_public_shares,
    );

    let (send_mint, receive_mint) = match order.side {
        OrderSide::Buy => (&order.quote_mint, &order.base_mint),
        OrderSide::Sell => (&order.base_mint, &order.quote_mint),
    };

    let (send_index, send_balance) =
        find_or_augment_balance(send_mint, &mut augmented_wallet, false /* augment */)
            .ok_or_else(|| ERR_BALANCE_NOT_FOUND.to_string())?;
    let (receive_index, receive_balance) =
        find_or_augment_balance(receive_mint, &mut augmented_wallet, true /* augment */)
            .ok_or_else(|| ERR_BALANCE_NOT_FOUND.to_string())?;

    // Find a balance to cover the fee
    let (_, fee_balance) = find_or_augment_balance(
        &fee.gas_addr,
        &mut augmented_wallet,
        false, // augment
    )
    .ok_or_else(|| ERR_BALANCE_NOT_FOUND.to_string())?;

    // Find the order in the wallet
    let order_index =
        find_order(&order, &augmented_wallet).ok_or_else(|| ERR_ORDER_NOT_FOUND.to_string())?;

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
    let statement = ValidCommitmentsStatement {
        indices: OrderSettlementIndices {
            order: order_index as u64,
            balance_send: send_index as u64,
            balance_receive: receive_index as u64,
        },
    };
    let witness = ValidCommitmentsWitness {
        private_secret_shares: valid_reblind_witness.reblinded_wallet_private_shares.clone(),
        public_secret_shares: valid_reblind_witness.reblinded_wallet_public_shares.clone(),
        augmented_public_shares,
        order,
        balance_send: send_balance,
        balance_receive: receive_balance,
        balance_fee: fee_balance,
        fee,
    };

    // Dispatch a job to the proof manager to prove `VALID COMMITMENTS`
    let (proof_sender, proof_receiver) = oneshot::channel();
    proof_manager_work_queue
        .send(ProofManagerJob {
            response_channel: proof_sender,
            type_: ProofJob::ValidCommitments { witness: witness.clone(), statement },
        })
        .map_err(|_| ERR_ENQUEUING_JOB.to_string())?;

    Ok((witness, proof_receiver))
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

            wallet.balances[empty_balance_ind] = Balance { mint: mint.clone(), amount: 0 };
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
pub(super) async fn update_wallet_validity_proofs(
    wallet: &Wallet,
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    global_state: RelayerState,
    network_sender: TokioSender<GossipOutbound>,
) -> Result<(), String> {
    // No validity proofs needed for an empty wallet, they will be re-proven on
    // the next update that adds a non-empty order
    if wallet.orders.values().all(|o| o.is_zero()) {
        return Ok(());
    }

    // Dispatch a proof of `VALID REBLIND` for the wallet
    let (reblind_witness, reblind_response_channel) =
        construct_wallet_reblind_proof(wallet, &proof_manager_work_queue)?;
    let wallet_reblind_witness = Box::new(reblind_witness);

    // For each order, construct a proof of `VALID COMMITMENTS`
    let mut commitments_response_channels = Vec::new();
    for (order_id, order) in wallet.orders.iter().filter(|(_id, o)| !o.is_zero()) {
        // Start a proof of `VALID COMMITMENTS`
        let (commitments_witness, response_channel) = construct_wallet_commitment_proof(
            wallet,
            order.clone(),
            &wallet_reblind_witness,
            &proof_manager_work_queue,
            global_state.disable_fee_validation,
        )?;

        let order_commitment_witness = Box::new(commitments_witness);

        // Attach a copy of the witness to the locally managed state
        // This witness is referenced by match computations which compute linkable
        // commitments to shared witness elements; i.e. they commit with the
        // same randomness
        {
            global_state
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

        commitments_response_channels.push((*order_id, response_channel));
    }

    // Await the proof of `VALID REBLIND`
    let reblind_proof: ValidReblindBundle =
        reblind_response_channel.await.map_err(|_| ERR_PROVE_REBLIND_FAILED.to_string())?.into();
    let reblind_proof = Box::new(reblind_proof);

    // Await proofs for each order, store them in the state
    for (order_id, receiver) in commitments_response_channels.into_iter() {
        // Await a proof
        let commitment_proof: ValidCommitmentsBundle =
            receiver.await.map_err(|_| ERR_PROVE_COMMITMENTS_FAILED.to_string())?.into();

        let proof_bundle = OrderValidityProofBundle {
            reblind_proof: reblind_proof.clone(),
            commitment_proof: Box::new(commitment_proof),
        };
        global_state.add_order_validity_proofs(&order_id, proof_bundle.clone()).await;

        // Gossip the updated proofs to the network
        let message = GossipOutbound::Pubsub {
            topic: ORDER_BOOK_TOPIC.to_string(),
            message: PubsubMessage::OrderBookManagement(
                OrderBookManagementMessage::OrderProofUpdated {
                    order_id,
                    cluster: global_state.local_cluster_id.clone(),
                    proof_bundle,
                },
            ),
        };
        network_sender.send(message).unwrap()
    }

    Ok(())
}
