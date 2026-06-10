//! Simulates the effect of wallet tasks on the relayer state
//!
//! The simulator projects the effect of QUEUED tasks onto an account view:
//! given the last applied account state and the tasks ahead of it in the
//! queue, it predicts the post-execution state. This powers speculative API
//! views and the divergence oracle (`simulation::oracle`), which compares
//! projections against actual post-task state to surface state-divergence
//! bugs (e.g. the 2026-06-09 `InvalidObligationAmountIn` class: a lagging
//! refresh re-inflating an `amount_in` that local settles had decremented).
//!
//! Simulation must NEVER panic: it runs on request-serving and task-driver
//! paths, and a panicking projection helper is strictly worse than an
//! incomplete one. Unsupported effects return errors or are skipped with a
//! log so callers degrade to the unprojected state.

use state::State;
use types_account::{Account, OrderId, balance::BalanceLocation};
use types_core::{AccountId, MatchResult};
use types_tasks::{
    CreateBalanceTaskDescriptor, CreateOrderTaskDescriptor, DepositTaskDescriptor,
    NewAccountTaskDescriptor, QueuedTask, SettleInternalMatchTaskDescriptor,
    SettlePrivateMatchTaskDescriptor, TaskDescriptor, WithdrawTaskDescriptor,
};
use util::log_task;
use util::logging::Outcome;

use super::error::TaskSimulationError;
use crate::logging::Task;

// ----------
// | Errors |
// ----------

/// The error message emitted when the wallet id for a given task does not match
const ERR_INVALID_ACCOUNT_ID: &str = "Task does not apply to account";
/// The error message emitted when a settled order is missing from the account
const ERR_SETTLE_ORDER_NOT_FOUND: &str = "settled order not found in account";
/// The error message emitted when a withdrawal's balance is missing
const ERR_WITHDRAW_BALANCE_NOT_FOUND: &str = "withdrawn balance not found in account";
/// The error message emitted when a withdrawal exceeds the projected balance
const ERR_WITHDRAW_INSUFFICIENT: &str = "withdrawal exceeds projected balance";

// ----------
// | Report |
// ----------

/// The result of projecting a set of queued tasks onto an account
#[derive(Clone, Debug, Default)]
pub struct SimulationReport {
    /// Whether a `RefreshAccount` task is queued.
    ///
    /// A refresh REPLACES account state from the indexer, which cannot be
    /// projected locally (it depends on network data). When set, the
    /// projection should be treated as unreliable: every confusing view
    /// during the 2026-06-09 refresh storms ("wallet not found", stale
    /// `amount_in`) occurred in exactly this window.
    pub refresh_pending: bool,
    /// The display names of tasks that were skipped (not projected)
    pub skipped_tasks: Vec<String>,
}

// --------------
// | Simulation |
// --------------

/// Simulate the effect of tasks on an account, mutates the account in place
///
/// Returns a [`SimulationReport`] describing the fidelity of the projection.
pub fn simulate_account_tasks(
    account: &mut Account,
    tasks: Vec<QueuedTask>,
    state: &State,
) -> Result<SimulationReport, TaskSimulationError> {
    let mut report = SimulationReport::default();
    for task in tasks {
        if matches!(task.descriptor, TaskDescriptor::RefreshAccount(_)) {
            report.refresh_pending = true;
        }

        if !should_simulate(&task) {
            let task_type = task.descriptor.display_description();
            log_task!(
                Task::TaskSimulation,
                Outcome::Skipped,
                subject = %task.id,
                task_type = %task_type,
                "skipping simulation for task"
            );
            report.skipped_tasks.push(task_type);
            continue;
        }

        simulate_single_account_task(account, task.descriptor, state)?;
    }

    Ok(report)
}

/// Determine if the task should be simulated
fn should_simulate(task: &QueuedTask) -> bool {
    match task.descriptor {
        // The account view being projected onto already exists
        TaskDescriptor::NewAccount(_) => false,
        TaskDescriptor::CreateOrder(_) => true,
        TaskDescriptor::Deposit(_) => true,
        TaskDescriptor::CreateBalance(_) => true,
        TaskDescriptor::SettleInternalMatch(_) => true,
        TaskDescriptor::SettlePrivateMatch(_) => true,
        TaskDescriptor::Withdraw(_) => true,
        // Cancel order removes from local state after on-chain tx succeeds
        TaskDescriptor::CancelOrder(_) => false,
        // External matches bypass the task queue and are not simulated
        TaskDescriptor::SettleExternalMatch(_) => false,
        TaskDescriptor::NodeStartup(_) => false,
        // A refresh replaces state from the indexer; it cannot be projected
        // locally. Reported via `SimulationReport::refresh_pending`.
        TaskDescriptor::RefreshAccount(_) => false,
    }
}

/// Simulate the effect of a single task on a wallet
pub(crate) fn simulate_single_account_task(
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
        TaskDescriptor::SettlePrivateMatch(t) => simulate_settle_private_match(account, &t),
        TaskDescriptor::Withdraw(t) => simulate_withdraw(account, &t),
        // Ignore all non-wallet tasks
        TaskDescriptor::CancelOrder(_) => Ok(()),
        TaskDescriptor::SettleExternalMatch(_) => Ok(()),
        TaskDescriptor::NodeStartup(_) => Ok(()),
        TaskDescriptor::RefreshAccount(_) => Ok(()),
    }
}

/// Simulate a `NewAccount` task applied to a wallet
///
/// The account view being projected onto already exists, so this only
/// validates the task's target; there is no state to apply. Takes `&mut` to
/// keep a uniform simulator signature.
#[allow(clippy::needless_pass_by_ref_mut)]
fn simulate_new_account(
    account: &mut Account,
    desc: &NewAccountTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    if desc.account_id != account.id {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_ACCOUNT_ID));
    }

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
fn simulate_settle_internal_match(
    account: &mut Account,
    desc: &SettleInternalMatchTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    simulate_settle_match(
        account,
        desc.account_id,
        desc.other_account_id,
        desc.order_id,
        desc.other_order_id,
        &desc.match_result,
    )
}

/// Simulate a `SettlePrivateMatch` task applied to a wallet
fn simulate_settle_private_match(
    account: &mut Account,
    desc: &SettlePrivateMatchTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    simulate_settle_match(
        account,
        desc.account_id,
        desc.other_account_id,
        desc.order_id,
        desc.other_order_id,
        &desc.match_result,
    )
}

/// Simulate a match settlement applied to one party's account
///
/// Mirrors the real settlement's state updates (e.g.
/// `update_ring0_intent_after_match`): the party's order has its `amount_in`
/// decremented by the obligation and is marked filled, the input balance is
/// debited, and the output balance is credited if a record for it exists.
///
/// Fidelity notes:
/// - `decrement_amount_in` clamps rather than underflowing, matching the
///   applicator's behavior for stale/over-committed matches.
/// - The output credit uses the obligation's pre-fee `amount_out`, so the
///   projected output balance is an upper bound. The input-side debit and the
///   order decrement -- the fields that determine matchable amount, and the
///   ones implicated in the phantom-liquidity / `InvalidObligationAmountIn`
///   bug class -- are exact.
/// - A missing output-balance record is skipped rather than created: creating
///   one requires authority data the descriptor does not carry, and the real
///   settlement materializes it on-chain/via sync.
fn simulate_settle_match(
    account: &mut Account,
    account_id: AccountId,
    other_account_id: AccountId,
    order_id: OrderId,
    other_order_id: OrderId,
    match_result: &MatchResult,
) -> Result<(), TaskSimulationError> {
    // Party 0 is the initiating `account_id`, party 1 the counterparty;
    // see `SettleInternalMatchTask::get_obligation`
    let (obligation, oid) = if account.id == account_id {
        (&match_result.party0_obligation, order_id)
    } else if account.id == other_account_id {
        (&match_result.party1_obligation, other_order_id)
    } else {
        return Err(TaskSimulationError::InvalidTask(ERR_INVALID_ACCOUNT_ID));
    };

    // Apply the fill to the order
    let order = account
        .orders
        .get_mut(&oid)
        .ok_or(TaskSimulationError::InvalidWalletState(ERR_SETTLE_ORDER_NOT_FOUND))?;
    let location = order.ring.balance_location();
    order.decrement_amount_in(obligation.amount_in);
    order.metadata.mark_filled();

    // Debit the input balance; saturate rather than underflow -- settlement
    // revalidation rejects over-committed matches before they execute, so a
    // shortfall here is a projection-level divergence, not a crash
    if let Some(balance) = account.get_balance_mut(&obligation.input_token, location) {
        let debited = balance.amount().saturating_sub(obligation.amount_in);
        *balance.amount_mut() = debited;
    }

    // Credit the output balance (pre-fee) if a record for it exists
    if let Some(balance) = account.get_balance_mut(&obligation.output_token, location) {
        let credited = balance.amount().saturating_add(obligation.amount_out);
        *balance.amount_mut() = credited;
    }

    Ok(())
}

/// Simulate a `Withdraw` task applied to a wallet
///
/// Mirrors the real withdraw task: the darkpool balance for the token is
/// decremented by the withdrawn amount.
fn simulate_withdraw(
    account: &mut Account,
    desc: &WithdrawTaskDescriptor,
) -> Result<(), TaskSimulationError> {
    let balance = account
        .get_darkpool_balance_mut(&desc.token)
        .ok_or(TaskSimulationError::InvalidWalletState(ERR_WITHDRAW_BALANCE_NOT_FOUND))?;

    let amount = balance.amount();
    if desc.amount > amount {
        return Err(TaskSimulationError::InvalidWalletState(ERR_WITHDRAW_INSUFFICIENT));
    }

    *balance.amount_mut() = amount - desc.amount;
    Ok(())
}

#[cfg(test)]
mod test {
    use alloy::primitives::Address;
    use circuit_types::Amount;
    use circuit_types::schnorr::SchnorrPrivateKey;
    use darkpool_types::settlement_obligation::SettlementObligation;
    use types_account::OrderId;
    use types_account::account::mocks::{mock_empty_account, mock_intent};
    use types_account::order::{OrderMetadata, PrivacyRing};
    use types_core::MatchResult;

    use super::*;

    /// The base (input) token for the test order
    fn base_token() -> Address {
        Address::with_last_byte(1)
    }

    /// The quote (output) token for the test order
    fn quote_token() -> Address {
        Address::with_last_byte(2)
    }

    /// Build an account holding one Ring0 sell order (base -> quote) of
    /// `amount_in`, with an EOA input balance of `balance_amount`
    fn setup_account(amount_in: Amount, balance_amount: Amount) -> (Account, OrderId) {
        let mut account = mock_empty_account();
        let mut intent = mock_intent();
        intent.in_token = base_token();
        intent.out_token = quote_token();
        intent.amount_in = amount_in;

        let order_id = OrderId::new_v4();
        account.place_order(order_id, intent, PrivacyRing::Ring0, OrderMetadata::default());

        // Ring0 balances live in the EOA
        let authority = SchnorrPrivateKey::random().public_key();
        let owner = Address::with_last_byte(3);
        let fee_recipient = Address::with_last_byte(4);
        account.create_eoa_balance(base_token(), owner, fee_recipient, authority);
        account
            .deposit_balance(base_token(), balance_amount, BalanceLocation::EOA)
            .expect("deposit");

        (account, order_id)
    }

    /// Build a match result in which the test account (party 0) sells
    /// `base_amount` of the base token for `quote_amount` of the quote token
    fn match_result(base_amount: Amount, quote_amount: Amount) -> MatchResult {
        let party0 = SettlementObligation {
            input_token: base_token(),
            output_token: quote_token(),
            amount_in: base_amount,
            amount_out: quote_amount,
        };
        let party1 = SettlementObligation {
            input_token: quote_token(),
            output_token: base_token(),
            amount_in: quote_amount,
            amount_out: base_amount,
        };
        MatchResult::new(party0, party1)
    }

    /// A settle decrements the initiator's order and input balance and marks
    /// the order filled
    #[test]
    fn test_settle_simulation_initiator() {
        let (mut account, order_id) = setup_account(100, 100);
        let other_account = AccountId::new_v4();
        let other_order = OrderId::new_v4();
        let account_id = account.id;

        simulate_settle_match(
            &mut account,
            account_id,
            other_account,
            order_id,
            other_order,
            &match_result(40, 80),
        )
        .expect("settle simulation");

        let order = account.get_order(&order_id).expect("order");
        assert_eq!(order.amount_in(), 60, "order must be decremented by the fill");
        assert!(order.metadata.has_been_filled, "order must be marked filled");

        let balance = account.get_eoa_balance(&base_token()).expect("balance");
        assert_eq!(balance.amount(), 60, "input balance must be debited");
    }

    /// The counterparty side applies party 1's obligation to the other order
    #[test]
    fn test_settle_simulation_counterparty() {
        // The simulated account holds the COUNTERPARTY order: it sells quote
        // for base, so its input balance is in the quote token
        let mut account = mock_empty_account();
        let mut intent = mock_intent();
        intent.in_token = quote_token();
        intent.out_token = base_token();
        intent.amount_in = 200;

        let other_order = OrderId::new_v4();
        account.place_order(other_order, intent, PrivacyRing::Ring0, OrderMetadata::default());
        let authority = SchnorrPrivateKey::random().public_key();
        account.create_eoa_balance(
            quote_token(),
            Address::with_last_byte(3),
            Address::with_last_byte(4),
            authority,
        );
        account.deposit_balance(quote_token(), 200, BalanceLocation::EOA).expect("deposit");

        let initiator = AccountId::new_v4();
        let initiator_order = OrderId::new_v4();
        let account_id = account.id;
        simulate_settle_match(
            &mut account,
            initiator,
            account_id,
            initiator_order,
            other_order,
            &match_result(40, 80),
        )
        .expect("settle simulation");

        // Party 1 sells 80 quote for 40 base
        let order = account.get_order(&other_order).expect("order");
        assert_eq!(order.amount_in(), 120, "counterparty order must be decremented");
        assert!(order.metadata.has_been_filled);
        let balance = account.get_eoa_balance(&quote_token()).expect("balance");
        assert_eq!(balance.amount(), 120, "counterparty input balance must be debited");
    }

    /// A settle for an unrelated account is rejected, and a missing order
    /// errors rather than panicking
    #[test]
    fn test_settle_simulation_errors() {
        let (mut account, order_id) = setup_account(100, 100);
        let mr = match_result(40, 80);

        // Unrelated account ids
        let res = simulate_settle_match(
            &mut account,
            AccountId::new_v4(),
            AccountId::new_v4(),
            order_id,
            OrderId::new_v4(),
            &mr,
        );
        assert!(matches!(res, Err(TaskSimulationError::InvalidTask(_))));

        // Missing order
        let account_id = account.id;
        let res = simulate_settle_match(
            &mut account,
            account_id,
            AccountId::new_v4(),
            OrderId::new_v4(), // not in the account
            OrderId::new_v4(),
            &mr,
        );
        assert!(matches!(res, Err(TaskSimulationError::InvalidWalletState(_))));
    }

    /// Regression for the 2026-06-09 phantom-liquidity class: after projected
    /// fills, the matchable amount must reflect the decremented `amount_in`
    /// and debited balance -- a projection that re-inflates either re-offers
    /// phantom liquidity and oversizes the next obligation
    /// (`InvalidObligationAmountIn`)
    #[test]
    fn test_settle_simulation_no_phantom_liquidity() {
        let (mut account, order_id) = setup_account(100, 100);
        let other_account = AccountId::new_v4();
        let other_order = OrderId::new_v4();
        let account_id = account.id;

        // Two sequential partial fills
        for _ in 0..2 {
            simulate_settle_match(
                &mut account,
                account_id,
                other_account,
                order_id,
                other_order,
                &match_result(30, 60),
            )
            .expect("settle simulation");
        }

        let order = account.get_order(&order_id).expect("order").clone();
        assert_eq!(order.amount_in(), 40);
        let matchable = account.get_matchable_amount_for_order(&order);
        assert_eq!(matchable, 40, "matchable must track fills exactly");
    }

    /// Withdraw decrements the darkpool balance and rejects over-withdrawal
    #[test]
    fn test_withdraw_simulation() {
        let mut account = mock_empty_account();
        let authority = SchnorrPrivateKey::random().public_key();
        account.create_darkpool_balance(
            base_token(),
            Address::with_last_byte(3),
            Address::with_last_byte(4),
            authority,
        );
        account.deposit_balance(base_token(), 100, BalanceLocation::Darkpool).expect("deposit");

        let desc = WithdrawTaskDescriptor {
            account_id: account.id,
            token: base_token(),
            amount: 60,
            signature: vec![],
        };
        simulate_withdraw(&mut account, &desc).expect("withdraw simulation");
        assert_eq!(account.get_darkpool_balance(&base_token()).unwrap().amount(), 40);

        // Over-withdrawal must error, not underflow
        let over = WithdrawTaskDescriptor { amount: 100, ..desc };
        let res = simulate_withdraw(&mut account, &over);
        assert!(matches!(res, Err(TaskSimulationError::InvalidWalletState(_))));
    }
}
