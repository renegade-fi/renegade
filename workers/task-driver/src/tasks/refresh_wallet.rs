//! Refresh a wallet from on-chain state

// --------------
// | Task State |
// --------------

use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Display},
};

use async_trait::async_trait;
use circuit_types::SizedWalletShare;
use common::types::{
    tasks::RefreshWalletTaskDescriptor,
    wallet::{Wallet, WalletIdentifier},
};
use constants::Scalar;
use darkpool_client::errors::DarkpoolClientError;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};

use crate::{
    task_state::StateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::{
        find_wallet::{find_latest_wallet_tx, gen_private_shares},
        merkle_path::find_merkle_path,
        validity_proofs::update_wallet_validity_proofs,
    },
};

/// The task name
const REFRESH_WALLET_TASK_NAME: &str = "refresh-wallet";

/// Error emitted when the wallet is not found in contract storage
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

/// Defines the state of the refresh wallet task
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefreshWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for RefreshWalletTaskState {
    fn commit_point() -> Self {
        // We use `FindingWallet` as the commit point.
        // Otherwise, if this task were to be preempted during `FindingWallet`,
        // it's possible that we'd leave freshly-indexed orders without validity proofs
        // in the state.
        RefreshWalletTaskState::FindingWallet
    }

    fn completed(&self) -> bool {
        matches!(self, RefreshWalletTaskState::Completed)
    }
}

impl Display for RefreshWalletTaskState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RefreshWalletTaskState::Pending => write!(f, "Pending"),
            RefreshWalletTaskState::FindingWallet => write!(f, "Finding Wallet"),
            RefreshWalletTaskState::CreatingValidityProofs => write!(f, "Creating Validity Proofs"),
            RefreshWalletTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<RefreshWalletTaskState> for StateWrapper {
    fn from(state: RefreshWalletTaskState) -> Self {
        StateWrapper::RefreshWallet(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the wallet refresh task
#[derive(Clone, Debug)]
pub enum RefreshWalletTaskError {
    /// Wallet was not found in contract storage
    NotFound(String),
    /// Error generating a proof of `VALID COMMITMENTS`
    ProofGeneration(String),
    /// Error interacting with the darkpool
    Darkpool(String),
    /// Error interacting with state
    State(String),
}

impl TaskError for RefreshWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            RefreshWalletTaskError::Darkpool(_)
                | RefreshWalletTaskError::ProofGeneration(_)
                | RefreshWalletTaskError::State(_)
        )
    }
}

impl Display for RefreshWalletTaskError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RefreshWalletTaskError {}

impl From<StateError> for RefreshWalletTaskError {
    fn from(e: StateError) -> Self {
        RefreshWalletTaskError::State(e.to_string())
    }
}

impl From<DarkpoolClientError> for RefreshWalletTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        RefreshWalletTaskError::Darkpool(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to refresh a wallet from on-chain state
pub struct RefreshWalletTask {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The state of the task's execution
    pub task_state: RefreshWalletTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for RefreshWalletTask {
    type State = RefreshWalletTaskState;
    type Error = RefreshWalletTaskError;
    type Descriptor = RefreshWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet_id: descriptor.wallet_id,
            task_state: RefreshWalletTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            RefreshWalletTaskState::Pending => {
                self.task_state = RefreshWalletTaskState::FindingWallet
            },

            RefreshWalletTaskState::FindingWallet => {
                // If the wallet is not up to date, or is missing any validity proofs,
                // we need to create validity proofs for the wallet
                let should_create_validity_proofs =
                    !self.find_wallet().await? || self.wallet_missing_validity_proofs().await?;

                if should_create_validity_proofs {
                    self.task_state = RefreshWalletTaskState::CreatingValidityProofs;
                } else {
                    self.task_state = RefreshWalletTaskState::Completed;
                }
            },

            RefreshWalletTaskState::CreatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = RefreshWalletTaskState::Completed;
            },

            RefreshWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        REFRESH_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }
}

impl Descriptor for RefreshWalletTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl RefreshWalletTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Find the wallet in contract storage
    ///
    /// Returns `true` if the wallet is up to date, `false` otherwise
    async fn find_wallet(&self) -> Result<bool, RefreshWalletTaskError> {
        // First, check if the wallet's public blinder is used on-chain
        // If not, the local view of the wallet is up to date and we can use the
        // shares we have locally
        let curr_wallet = self.get_wallet().await?;
        if !self.is_public_blinder_used(curr_wallet.next_public_blinder()).await? {
            info!("next public blinder not used, wallet is up to date");
            return Ok(true);
        }

        let (public_share, private_share) = self.find_wallet_shares(&curr_wallet).await?;
        let mut wallet = Wallet::new_from_shares(
            self.wallet_id,
            curr_wallet.key_chain.secret_keys.clone(),
            public_share,
            private_share,
        );

        // Update the merkle proof for the wallet, then write to state
        let merkle_proof = find_merkle_path(&wallet, &self.ctx).await?;
        wallet.merkle_proof = Some(merkle_proof);

        // Match up order IDs from the existing wallet with those in the refreshed
        // wallet to keep them consistent across refreshes
        matchup_order_ids(&curr_wallet, &mut wallet)?;

        let waiter = self.ctx.state.update_wallet(wallet.clone()).await?;
        waiter.await?;
        Ok(false)
    }

    /// Update validity proofs for the wallet
    async fn update_validity_proofs(&self) -> Result<(), RefreshWalletTaskError> {
        let wallet = self.get_wallet().await?;
        update_wallet_validity_proofs(&wallet, &self.ctx)
            .await
            .map_err(RefreshWalletTaskError::ProofGeneration)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the wallet from the state
    async fn get_wallet(&self) -> Result<Wallet, RefreshWalletTaskError> {
        self.ctx
            .state
            .get_wallet(&self.wallet_id)
            .await?
            .ok_or_else(|| RefreshWalletTaskError::NotFound(ERR_WALLET_NOT_FOUND.to_string()))
    }

    /// Find the latest wallet shares from on-chain
    ///
    /// Returns the public shares and private shares in order
    async fn find_wallet_shares(
        &self,
        wallet: &Wallet,
    ) -> Result<(SizedWalletShare, SizedWalletShare), RefreshWalletTaskError> {
        let (public_blinder, private_share) = self.get_latest_shares(wallet).await?;

        // Fetch public shares from on-chain
        let blinded_public_shares =
            self.ctx.darkpool_client.fetch_public_shares_for_blinder(public_blinder).await?;
        Ok((blinded_public_shares, private_share))
    }

    /// Check if the given public blinder is used on-chain
    async fn is_public_blinder_used(
        &self,
        public_blinder: Scalar,
    ) -> Result<bool, RefreshWalletTaskError> {
        let is_used = self.ctx.darkpool_client.is_public_blinder_used(public_blinder).await?;
        Ok(is_used)
    }

    /// Get the latest known shares on-chain
    ///
    /// Returns the public blinder share and the private shares
    async fn get_latest_shares(
        &self,
        wallet: &Wallet,
    ) -> Result<(Scalar, SizedWalletShare), RefreshWalletTaskError> {
        // Otherwise lookup the wallet
        let blinder_seed = wallet.private_blinder_share();
        let (idx, blinder, private_blinder_share) =
            find_latest_wallet_tx(blinder_seed, &self.ctx.darkpool_client)
                .await
                .map_err(|e| RefreshWalletTaskError::NotFound(e.to_string()))?;

        // Construct private shares from the blinder index
        let share_seed = wallet.get_last_private_share();
        let private_shares = gen_private_shares(idx, share_seed, private_blinder_share);

        let public_blinder = blinder - private_blinder_share;
        Ok((public_blinder, private_shares))
    }

    /// Check if the wallet is missing validity proofs for any of its matchable
    /// orders
    async fn wallet_missing_validity_proofs(&self) -> Result<bool, RefreshWalletTaskError> {
        let wallet = self.get_wallet().await?;
        let matchable_orders = wallet.get_matchable_orders();

        for (order_id, _) in matchable_orders {
            if self.ctx.state.get_validity_proofs(&order_id).await?.is_none() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

// ----------------------
// | Non-Member Helpers |
// ----------------------

/// Match up the order IDs from the existing wallet with those in the
/// refreshed wallet where possible
fn matchup_order_ids(
    existing: &Wallet,
    refreshed: &mut Wallet,
) -> Result<(), RefreshWalletTaskError> {
    // We can only use any existing order ID once to overwrite a refreshed order. So
    // we track which ones have already been used using this set
    let mut used_existing_ids = HashSet::new();

    for (refreshed_id, refreshed_order) in refreshed.orders.iter_mut() {
        // Find an order in the existing wallet that matches the refreshed order and
        // hasn't been used yet to overwrite a refreshed order
        let maybe_order = existing.orders.iter().find(|(id, existing_order)| {
            let same_pair_side = existing_order.pair_and_side() == refreshed_order.pair_and_side();
            let not_already_matched = !used_existing_ids.contains(id);
            same_pair_side && not_already_matched
        });

        if let Some((existing_id, existing_order)) = maybe_order {
            *refreshed_id = *existing_id;
            refreshed_order.min_fill_size = existing_order.min_fill_size;
            refreshed_order.allow_external_matches = existing_order.allow_external_matches;
            used_existing_ids.insert(*existing_id);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use common::types::{
        wallet::OrderIdentifier,
        wallet_mocks::{mock_empty_wallet, mock_order},
    };

    use super::*;

    /// Tests the basic case in which the existing wallet has a single order and
    /// the refreshed wallet has a single order with a different ID
    #[test]
    fn test_matchup_order_ids_single_order() {
        let mut existing = mock_empty_wallet();
        let mut refreshed = mock_empty_wallet();

        let id1 = OrderIdentifier::new_v4();
        let id2 = OrderIdentifier::new_v4();
        let order = mock_order();
        existing.orders.insert(id1, order.clone());
        refreshed.orders.insert(id2, order.clone());

        matchup_order_ids(&existing, &mut refreshed).unwrap();
        assert_eq!(refreshed.orders.keys().next(), Some(&id1));

        // Verify that the order was not modified
        assert_eq!(refreshed.orders.get(&id1), existing.orders.get(&id1));
    }

    /// Tests the case in which the existing wallet has multiple _equal_ orders
    /// and the refreshed wallet has multiple _equal_ orders with different IDs
    #[test]
    fn test_matchup_order_ids_identical_orders() {
        let mut existing = mock_empty_wallet();
        let mut refreshed = mock_empty_wallet();

        let id1 = OrderIdentifier::new_v4();
        let id2 = OrderIdentifier::new_v4();
        let id3 = OrderIdentifier::new_v4();
        let id4 = OrderIdentifier::new_v4();

        let order = mock_order();

        existing.orders.insert(id1, order.clone());
        existing.orders.insert(id2, order.clone());

        refreshed.orders.insert(id3, order.clone());
        refreshed.orders.insert(id4, order.clone());

        matchup_order_ids(&existing, &mut refreshed).unwrap();

        let expected_ids = HashSet::from([id1, id2]);
        let refreshed_ids: HashSet<_> = refreshed.orders.keys().cloned().collect();
        assert_eq!(refreshed_ids, expected_ids);

        // Verify that the orders are equivalent
        assert_eq!(refreshed.orders.get(&id1), existing.orders.get(&id1));
        assert_eq!(refreshed.orders.get(&id2), existing.orders.get(&id2));
    }

    /// Tests the case in which the existing wallet has a single order and the
    /// refreshed wallet has multiple equal orders with different IDs
    #[test]
    fn test_matchup_order_ids_partial_match() {
        let mut existing = mock_empty_wallet();
        let mut refreshed = mock_empty_wallet();

        let id1 = OrderIdentifier::new_v4();
        let id2 = OrderIdentifier::new_v4();
        let id3 = OrderIdentifier::new_v4();

        let order = mock_order();

        existing.orders.insert(id1, order.clone());

        refreshed.orders.insert(id2, order.clone());
        refreshed.orders.insert(id3, order.clone());

        matchup_order_ids(&existing, &mut refreshed).unwrap();

        let expected_ids = HashSet::from([id1, id3]);
        let refreshed_ids: HashSet<_> = refreshed.orders.keys().cloned().collect();
        assert_eq!(refreshed_ids, expected_ids);

        assert!(refreshed.orders.contains_key(&id1));
        assert!(refreshed.orders.contains_key(&id3));
        assert!(!refreshed.orders.contains_key(&id2));
    }

    /// Tests matching up order ids after an order has been partially filled
    #[test]
    fn test_matchup_order_ids_after_fill() {
        let mut existing = mock_empty_wallet();
        let mut refreshed = mock_empty_wallet();

        let id1 = OrderIdentifier::new_v4();
        let id2 = OrderIdentifier::new_v4();
        let id3 = OrderIdentifier::new_v4();
        let id4 = OrderIdentifier::new_v4();

        let order = mock_order();
        let order2 = mock_order();
        let mut filled_order = order.clone();
        filled_order.amount = 0; // Order was completely filled

        existing.orders.insert(id1, order.clone());
        existing.orders.insert(id2, order2.clone());
        refreshed.orders.insert(id3, filled_order.clone());
        refreshed.orders.insert(id4, order.clone()); // The existing order should only match the first order

        matchup_order_ids(&existing, &mut refreshed).unwrap();

        let expected_ids = HashSet::from([id1, id4]);
        let refreshed_ids: HashSet<_> = refreshed.orders.keys().cloned().collect();
        assert_eq!(refreshed_ids, expected_ids);
    }
}
