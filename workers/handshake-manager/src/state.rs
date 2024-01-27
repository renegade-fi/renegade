//! Defines a state machine and tracking mechanism for in-flight handshakes
// TODO: Remove this lint allowance
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use super::error::HandshakeManagerError;
use circuit_types::fixed_point::FixedPoint;
use common::{
    new_async_shared,
    types::{
        handshake::{ConnectionRole, HandshakeState},
        wallet::OrderIdentifier,
    },
    AsyncShared,
};
use constants::Scalar;
use crossbeam::channel::Sender;
use state::State;
use uuid::Uuid;

/// Error message thrown when a nullifier cannot be found
const ERR_NULLIFIER_MISSING: &str = "nullifier not found for order";

/// Holds state information for all in-flight handshake correspondences
///
/// Abstracts mostly over the concurrent access patterns used by the thread pool
/// of handshake executors
#[derive(Clone)]
pub struct HandshakeStateIndex {
    /// The underlying map of request identifiers to state machine instances
    state_map: AsyncShared<HashMap<Uuid, HandshakeState>>,
    /// A mapping from nullifier to a set of request_ids on that nullifier
    nullifier_map: AsyncShared<HashMap<Scalar, HashSet<Uuid>>>,
    /// A copy of the relayer global state
    global_state: State,
}

impl HandshakeStateIndex {
    /// Creates a new instance of the state index
    pub fn new(global_state: State) -> Self {
        Self {
            state_map: new_async_shared(HashMap::new()),
            nullifier_map: new_async_shared(HashMap::new()),
            global_state,
        }
    }

    // ----------------------------
    // | Index Management Methods |
    // ----------------------------

    /// Adds a new handshake to the state where the peer's order is already
    /// known (e.g. the peer initiated the handshake)
    #[allow(clippy::too_many_arguments)]
    pub async fn new_handshake(
        &self,
        request_id: Uuid,
        role: ConnectionRole,
        peer_order_id: OrderIdentifier,
        local_order_id: OrderIdentifier,
        execution_price: FixedPoint,
    ) -> Result<(), HandshakeManagerError> {
        // Lookup the public share nullifiers for the order
        let state = &self.global_state;
        let local_nullifier = state
            .get_nullifier_for_order(&local_order_id)?
            .ok_or_else(|| HandshakeManagerError::State(ERR_NULLIFIER_MISSING.to_string()))?;
        let peer_nullifier = state
            .get_nullifier_for_order(&peer_order_id)?
            .ok_or_else(|| HandshakeManagerError::State(ERR_NULLIFIER_MISSING.to_string()))?;

        // Index by request ID
        {
            let mut locked_state = self.state_map.write().await;
            locked_state.insert(
                request_id,
                HandshakeState::new(
                    request_id,
                    role,
                    peer_order_id,
                    local_order_id,
                    peer_nullifier,
                    local_nullifier,
                    execution_price,
                ),
            );
        } // locked_state released

        // Index by nullifier
        {
            let mut locked_nullifier_map = self.nullifier_map.write().await;
            locked_nullifier_map.entry(local_nullifier).or_default().insert(request_id);
            locked_nullifier_map.entry(peer_nullifier).or_default().insert(request_id);
        } // locked_nullifier_map released

        Ok(())
    }

    /// Removes a handshake after processing is complete; either by match
    /// completion or error
    pub async fn remove_handshake(&self, request_id: &Uuid) -> Option<HandshakeState> {
        // Remove from the state
        let state = {
            let mut locked_state = self.state_map.write().await;
            locked_state.remove(request_id)
        }; // locked_state released

        // Remove from the nullifier index
        if let Some(state) = state.clone() {
            let mut locked_nullifier_map = self.nullifier_map.write().await;

            if let Some(nullifier_set) = locked_nullifier_map.get_mut(&state.local_share_nullifier)
            {
                nullifier_set.remove(request_id);
            }

            if let Some(nullifier_set) = locked_nullifier_map.get_mut(&state.peer_share_nullifier) {
                nullifier_set.remove(request_id);
            }
        } // locked_nullifier_map released

        state
    }

    /// Shootdown all active handshakes on a given nullifier
    pub async fn shootdown_nullifier(
        &self,
        nullifier: Scalar,
    ) -> Result<(), HandshakeManagerError> {
        let requests = {
            let mut locked_nullifier_map = self.nullifier_map.write().await;
            locked_nullifier_map.remove(&nullifier).unwrap_or_default()
        }; // locked_nullifier_map released

        // For each request, remove the state entry for the request and send a cancel
        // signal over the request's cancel channel if one has already been
        // allocated. The receiver of this channel is the worker running in the
        // MPC runtime
        for request in requests.iter() {
            if let Some(state) = self.remove_handshake(request).await
                && let Some(channel) = state.cancel_channel
            {
                channel
                    .send(())
                    .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;
            }
        }

        Ok(())
    }

    // --------------------
    // | State Transition |
    // --------------------

    /// Gets the state of the given handshake
    pub async fn get_state(&self, request_id: &Uuid) -> Option<HandshakeState> {
        let locked_state = self.state_map.read().await;
        locked_state.get(request_id).cloned()
    }

    /// Transition the given handshake into the MatchInProgress state
    pub async fn in_progress(&self, request_id: &Uuid, cancel_channel: Sender<()>) {
        let mut locked_state = self.state_map.write().await;
        if let Some(entry) = locked_state.get_mut(request_id) {
            entry.in_progress();
            entry.cancel_channel = Some(cancel_channel);
        }
    }

    /// Transition the given handshake into the Completed state
    pub async fn completed(&self, request_id: &Uuid) {
        {
            let mut locked_state = self.state_map.write().await;
            if let Some(entry) = locked_state.get_mut(request_id) {
                entry.completed()
            }
        } // locked_state released

        // For now, we simply remove the handshake from the state
        self.remove_handshake(request_id).await;
    }

    /// Transition the given handshake into the Error state
    pub async fn error(&self, request_id: &Uuid, err: HandshakeManagerError) {
        {
            let mut locked_state = self.state_map.write().await;
            if let Some(entry) = locked_state.get_mut(request_id) {
                entry.error(err.to_string())
            }
        } // locked_state released

        // For now we simply remove the handshake from the state
        self.remove_handshake(request_id).await;
    }
}
