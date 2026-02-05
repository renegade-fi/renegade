//! Simulates the effect of wallet tasks on the relayer state

use state::State;
use tracing::warn;
use types_account::{Account, balance::BalanceLocation};
use types_tasks::{
    CreateBalanceTaskDescriptor, CreateOrderTaskDescriptor, DepositTaskDescriptor,
    NewAccountTaskDescriptor, QueuedTask, SettleInternalMatchTaskDescriptor, TaskDescriptor,
    WithdrawTaskDescriptor,
};

use super::error::TaskSimulationError;

// ----------
// | Errors |
// ----------

/// The error message emitted when the wallet id for a given task does not match
const ERR_INVALID_ACCOUNT_ID: &str = "Task does not apply to account";

// --------------
// | Simulation |
// --------------

/// Simulate the effect of tasks on an account, mutates the account in place
pub fn simulate_account_tasks(
    account: &mut Account,
    tasks: Vec<QueuedTask>,
    state: &State,
) -> Result<(), TaskSimulationError> {
    for task in tasks {
        if !should_simulate(&task) {
            warn!("Skipping simulation for task {}", task.id);
            continue;
        }

        simulate_single_account_task(account, task.descriptor, state)?;
    }

    Ok(())
}

/// Determine if the task should be simulated
fn should_simulate(task: &QueuedTask) -> bool {
    match task.descriptor {
        TaskDescriptor::NewAccount(_) => false,
        TaskDescriptor::CreateOrder(_) => true,
        TaskDescriptor::Deposit(_) => true,
        TaskDescriptor::CreateBalance(_) => true,
        TaskDescriptor::SettleInternalMatch(_) => true,
        TaskDescriptor::Withdraw(_) => true,
        // Cancel order removes from local state after on-chain tx succeeds
        TaskDescriptor::CancelOrder(_) => false,
        // External matches bypass the task queue and are not simulated
        TaskDescriptor::SettleExternalMatch(_) => false,
        TaskDescriptor::NodeStartup(_) => false,
        TaskDescriptor::RefreshAccount(_) => false,
    }
}

/// Simulate the effect of a single task on a wallet
fn simulate_single_account_task(
    account: &mut Account,
    task: TaskDescriptor,
    state: &State,
) -> Result<(), TaskSimulationError> {
    match task {
        TaskDescriptor::NewAccount(t) => simulate_new_account(account, &t),
        TaskDescriptor::CreateOrder(t) => simulate_create_order(account, &t),
        TaskDescriptor::Deposit(t) => simulate_deposit(account, &t),
        TaskDescriptor::CreateBalance(t) => simulate_create_balance(account, &t, state),
        TaskDescriptor::SettleInternalMatch(t) => simulate_settle_internal_match(account, &t),
        TaskDescriptor::Withdraw(t) => simulate_withdraw(account, &t),
        // Ignore all non-wallet tasks
        TaskDescriptor::CancelOrder(_) => Ok(()),
        TaskDescriptor::SettleExternalMatch(_) => Ok(()),
        TaskDescriptor::NodeStartup(_) => Ok(()),
        TaskDescriptor::RefreshAccount(_) => Ok(()),
    }
}

/// Simulate a `NewAccount` task applied to a wallet
#[allow(clippy::needless_pass_by_ref_mut)]
fn simulate_new_account(
    account: &mut Account,
    desc: &NewAccountTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if desc.account_id != account.id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_ACCOUNT_ID));
    }

    warn!("TODO: Implement new account simulation");
    Ok(())
}

/// Simulate a `CreateOrder` task applied to a wallet
fn simulate_create_order(
    account: &mut Account,
    desc: &CreateOrderTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    account.place_order(desc.order_id, desc.intent.clone(), desc.ring, desc.metadata.clone());
    Ok(())
}

/// Simulate a `Deposit` task applied to a wallet
fn simulate_deposit(
    account: &mut Account,
    desc: &DepositTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    account.deposit_balance(desc.token, desc.amount, BalanceLocation::Darkpool)?;
    Ok(())
}

/// Simulate a `CreateBalance` task applied to a wallet
fn simulate_create_balance(
    account: &mut Account,
    desc: &CreateBalanceTaskDescriptor,
    state: &State,
) -> Result<(), TaskSimulationError> {
    // CreateBalance creates a new balance, similar to deposit but for a new balance
    let fee_recipient = state.get_relayer_fee_addr().map_err(TaskSimulationError::state)?;
    account.create_balance(
        desc.token,
        desc.from_address,
        fee_recipient,
        desc.authority,
        BalanceLocation::Darkpool,
    );
    Ok(())
}

/// Simulate a `SettleInternalMatch` task applied to a wallet
#[allow(clippy::needless_pass_by_ref_mut)]
fn simulate_settle_internal_match(
    _account: &mut Account,
    _desc: &SettleInternalMatchTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    todo!("Implement settle internal match simulation");
}

/// Simulate a `Withdraw` task applied to a wallet
#[allow(clippy::needless_pass_by_ref_mut)]
fn simulate_withdraw(
    _account: &mut Account,
    _desc: &WithdrawTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    warn!("TODO: Implement withdraw simulation");
    Ok(())
}
