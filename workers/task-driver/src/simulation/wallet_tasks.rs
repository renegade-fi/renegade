//! Simulates the effect of wallet tasks on the relayer state

use ark_mpc::PARTY0;
use common::types::{
    tasks::{
        NewWalletTaskDescriptor, PayOfflineFeeTaskDescriptor, SettleMatchInternalTaskDescriptor,
        SettleMatchTaskDescriptor, TaskDescriptor, UpdateWalletTaskDescriptor,
    },
    wallet::Wallet,
};
use util::matching_engine::{apply_match_to_shares, compute_fee_obligation};

use super::error::TaskSimulationError;

// ----------
// | Errors |
// ----------

/// The error message emitted when the wallet id for a given task does not match
const ERR_INVALID_WALLET_ID: &str = "Task does not apply to wallet";
/// The error message emitted when an order is missing from the wallet
const ERR_ORDER_MISSING: &str = "Order not found in wallet";
/// The error message emitted when a balance is missing from the wallet
const ERR_BALANCE_MISSING: &str = "Balance not found in wallet";

// --------------
// | Simulation |
// --------------

/// Simulate the effect of tasks on a wallet, mutates the wallet in place
pub fn simulate_wallet_tasks(
    wallet: &mut Wallet,
    tasks: Vec<TaskDescriptor>,
) -> Result<(), TaskSimulationError> {
    for task in tasks {
        simulate_single_wallet_task(wallet, task)?;
    }

    Ok(())
}

/// Simulate the effect of a single task on a wallet
fn simulate_single_wallet_task(
    wallet: &mut Wallet,
    task: TaskDescriptor,
) -> Result<(), TaskSimulationError> {
    match task {
        TaskDescriptor::NewWallet(desc) => {
            simulate_new_wallet(wallet, desc)?;
        },
        TaskDescriptor::UpdateWallet(desc) => {
            simulate_update_wallet(wallet, desc)?;
        },
        TaskDescriptor::SettleMatch(desc) => {
            simulate_settle_match(wallet, &desc)?;
        },
        TaskDescriptor::SettleMatchInternal(desc) => {
            simulate_settle_internal_match(wallet, &desc)?;
        },
        TaskDescriptor::OfflineFee(desc) => {
            simulate_offline_fee_payment(wallet, &desc)?;
        },

        // Ignore non-wallet tasks
        _ => (),
    };

    Ok(())
}

/// Simulate a `NewWallet` task applied to a wallet
fn simulate_new_wallet(
    wallet: &mut Wallet,
    desc: NewWalletTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if desc.wallet.wallet_id != wallet.wallet_id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_WALLET_ID));
    }

    *wallet = desc.wallet;
    Ok(())
}

/// Simulate an `UpdateWallet` task applied to a wallet
fn simulate_update_wallet(
    wallet: &mut Wallet,
    desc: UpdateWalletTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if desc.new_wallet.wallet_id != wallet.wallet_id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_WALLET_ID));
    }

    *wallet = desc.new_wallet;
    Ok(())
}

/// Simulate a `SettleMatch` task applied to a wallet
fn simulate_settle_match(
    wallet: &mut Wallet,
    desc: &SettleMatchTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if wallet.wallet_id != desc.wallet_id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_WALLET_ID));
    }

    let is_party0 = desc.handshake_state.role.get_party_id() == PARTY0;

    // Get the new public and private shares for the wallet
    wallet.reblind_wallet();
    let new_private = wallet.private_shares.clone();

    let statement = &desc.match_bundle.match_proof.statement;
    let new_public = if is_party0 {
        &statement.party0_modified_shares
    } else {
        &statement.party1_modified_shares
    };

    // Update the wallet
    wallet.update_from_shares(&new_private, new_public);
    Ok(())
}

/// Simulate a settle internal match task applied to a wallet
fn simulate_settle_internal_match(
    wallet: &mut Wallet,
    desc: &SettleMatchInternalTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    let is_party0 = if desc.wallet_id1 == wallet.wallet_id {
        true
    } else if desc.wallet_id2 == wallet.wallet_id {
        false
    } else {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_WALLET_ID));
    };

    // Compute fees
    let order_id = if is_party0 { desc.order_id1 } else { desc.order_id2 };
    let my_order = wallet
        .get_order(&order_id)
        .cloned()
        .ok_or(TaskSimulationError::InvalidTask(ERR_ORDER_MISSING))?;

    let fees = compute_fee_obligation(wallet.max_match_fee, my_order.side, &desc.match_result);

    // Get the new public and private shares
    let witness =
        if is_party0 { &desc.order1_validity_witness } else { &desc.order2_validity_witness };
    let indices = if is_party0 {
        &desc.order1_proof.commitment_proof.statement.indices
    } else {
        &desc.order2_proof.commitment_proof.statement.indices
    };

    let mut new_public = witness.commitment_witness.augmented_public_shares.clone();
    let new_private = witness.reblind_witness.reblinded_wallet_private_shares.clone();
    apply_match_to_shares(&mut new_public, indices, fees, &desc.match_result, my_order.side);

    // Update the wallet
    wallet.update_from_shares(&new_private, &new_public);
    Ok(())
}

/// Simulate offline fee payment
fn simulate_offline_fee_payment(
    wallet: &mut Wallet,
    desc: &PayOfflineFeeTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if desc.wallet_id != wallet.wallet_id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_WALLET_ID));
    }

    // Set the relevant fee to zero
    let balance = wallet
        .get_balance_mut(&desc.mint)
        .ok_or(TaskSimulationError::InvalidTask(ERR_BALANCE_MISSING))?;

    if desc.is_protocol_fee {
        balance.protocol_fee_balance = 0;
    } else {
        balance.relayer_fee_balance = 0;
    }

    wallet.reblind_wallet();

    Ok(())
}
