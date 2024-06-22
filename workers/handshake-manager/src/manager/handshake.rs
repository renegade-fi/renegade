//! Manager implementations for handling the handshake process before the MPC
//! begins. This include:
//!     1. Price agreements
//!     2. Order selection
//!     3. State management

use common::types::{handshake::ConnectionRole, wallet::OrderIdentifier};
use gossip_api::{
    pubsub::{
        cluster::{ClusterManagementMessage, ClusterManagementMessageType},
        PubsubMessage,
    },
    request_response::handshake::{
        AcceptMatchCandidate, HandshakeMessage, HandshakeMessageType, MatchRejectionReason,
        ProposeMatchCandidate, RejectMatchCandidate,
    },
};
use job_types::network_manager::{NetworkManagerControlSignal, NetworkManagerJob};
use portpicker::pick_unused_port;
use util::err_str;
use uuid::Uuid;

use crate::error::HandshakeManagerError;

use super::HandshakeExecutor;

/// Error message emitted when a wallet cannot be looked up in the global state
pub(crate) const ERR_NO_WALLET: &str = "wallet not found in state";
/// Error message emitted when an order cannot be found in the global state
pub(crate) const ERR_NO_ORDER: &str = "order not found in state";
/// Error message emitted when an order validity proof cannot be found
pub(crate) const ERR_NO_PROOF: &str = "no order validity proof found for order";
/// Error message emitted when price data cannot be found for a token pair
pub(crate) const ERR_NO_PRICE_DATA: &str = "no price data found for token pair";

impl HandshakeExecutor {
    // ----------------
    // | Job Handlers |
    // ----------------

    /// Perform a handshake with a peer
    pub async fn perform_handshake(
        &self,
        peer_order_id: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        if let Some(local_order_id) = self.choose_match_proposal(peer_order_id).await {
            // Choose a peer to match this order with
            let managing_peer = self.state.get_peer_managing_order(&peer_order_id).await?;
            if managing_peer.is_none() {
                // TODO: Lower the order priority for this order
                return Ok(());
            }
            let peer = managing_peer.unwrap();

            // Send a handshake message to the given peer_id
            let request_id = Uuid::new_v4();
            let price_vector = self.fetch_price_vector().await?;
            let message = HandshakeMessage {
                request_id,
                message_type: HandshakeMessageType::Propose(ProposeMatchCandidate {
                    peer_id: self.state.get_peer_id().await?,
                    peer_order: peer_order_id,
                    sender_order: local_order_id,
                    price_vector: price_vector.clone(),
                }),
            };
            self.send_message(peer, message, None /* response_channel */)?;

            // Determine the execution price for the new order
            let (base, quote) = self.token_pair_for_order(&local_order_id).await?;
            let (_, _, price) = price_vector
                .find_pair(&base, &quote)
                .ok_or_else(|| HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string()))?;

            self.handshake_state_index
                .new_handshake(
                    request_id,
                    ConnectionRole::Dialer,
                    peer_order_id,
                    local_order_id,
                    price,
                )
                .await?;
        }

        Ok(())
    }

    /// Respond to a handshake request from a peer
    pub async fn handle_handshake_message(
        &self,
        request_id: Uuid,
        message: HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, HandshakeManagerError> {
        match message.message_type {
            // A peer initiates a handshake by proposing a pair of orders to match, the local node
            // should decide whether to proceed with the match
            HandshakeMessageType::Propose(req) => {
                self.handle_propose_match_candidate(request_id, req).await.map(Some)
            },

            // A peer has rejected a proposed match candidate, this can happen for a number of
            // reasons, enumerated by the `reason` field in the message
            HandshakeMessageType::Reject(resp) => {
                self.handle_proposal_rejection(resp).await;
                Ok(None)
            },

            // The response to ProposeMatchCandidate, indicating whether the peers should initiate
            // an MPC; if the responding peer has the proposed order pair cached it will
            // indicate so and the two peers will abandon the handshake
            HandshakeMessageType::Accept(resp) => {
                self.handle_execute_match(request_id, resp).await?;
                Ok(None)
            },
        }
    }

    /// Handles a proposal from a peer to initiate a match on a pair of orders
    ///
    /// The local peer first checks that this pair has not been matched, and
    /// then proceeds to broker an MPC network for it
    async fn handle_propose_match_candidate(
        &self,
        request_id: Uuid,
        req: ProposeMatchCandidate,
    ) -> Result<HandshakeMessage, HandshakeManagerError> {
        // Only accept the proposed order pair if the peer's order has already been
        // verified by the local node
        if let Some(reason) = self.check_match_proposal(&req).await? {
            return self
                .reject_match_proposal(request_id, req.peer_order, req.sender_order, reason)
                .await;
        }

        let ProposeMatchCandidate { peer_id, peer_order: my_order, sender_order, price_vector } =
            req;

        let (base, quote) = self.token_pair_for_order(&my_order).await?;
        let (_, _, execution_price) = price_vector
            .find_pair(&base, &quote)
            .ok_or_else(|| HandshakeManagerError::NoPriceData(ERR_NO_PRICE_DATA.to_string()))?;

        // Add an entry to the handshake state index
        self.handshake_state_index
            .new_handshake(
                request_id,
                ConnectionRole::Listener,
                sender_order,
                my_order,
                execution_price,
            )
            .await?;

        // If the order pair has not been previously matched; broker an MPC connection
        // Choose a random open port to receive the connection on
        // the peer port can be a dummy value as the local node will take the role
        // of listener in the connection setup
        let local_port = pick_unused_port().expect("all ports taken");
        let job = NetworkManagerJob::internal(NetworkManagerControlSignal::BrokerMpcNet {
            request_id,
            peer_id,
            peer_port: 0,
            local_port,
            local_role: ConnectionRole::Listener,
        });

        self.network_channel.send(job).map_err(err_str!(HandshakeManagerError::SendMessage))?;

        // Send a pubsub message indicating intent to match on the given order pair
        // Cluster peers will then avoid scheduling this match until the match either
        // completes, or the cache entry's invisibility window times out
        let cluster_id = self.state.get_cluster_id().await?;
        let topic = cluster_id.get_management_topic();
        let msg = PubsubMessage::Cluster(ClusterManagementMessage {
            cluster_id,
            message_type: ClusterManagementMessageType::MatchInProgress(my_order, sender_order),
        });

        self.network_channel
            .send(NetworkManagerJob::pubsub(topic, msg))
            .map_err(err_str!(HandshakeManagerError::SendMessage))?;

        Ok(HandshakeMessage {
            request_id,
            message_type: HandshakeMessageType::Accept(AcceptMatchCandidate {
                peer_id: self.state.get_peer_id().await?,
                port: local_port,
                order1: my_order,
                order2: sender_order,
            }),
        })
    }

    /// Handles a rejected match proposal, possibly updating the cache for a
    /// missing entry
    async fn handle_proposal_rejection(&self, resp: RejectMatchCandidate) {
        let RejectMatchCandidate { peer_order: my_order, sender_order: peer_order, .. } = resp;
        if let MatchRejectionReason::Cached = resp.reason {
            // Update the local cache
            self.handshake_cache.write().await.mark_completed(my_order, peer_order)
        }
    }

    /// Handles the flow of executing a match after both parties have agreed on
    /// an order pair to attempt a match with
    async fn handle_execute_match(
        &self,
        request_id: Uuid,
        resp: AcceptMatchCandidate,
    ) -> Result<(), HandshakeManagerError> {
        let AcceptMatchCandidate { peer_id, order1, order2, .. } = resp;

        // Cache the result of a handshake
        self.handshake_cache.write().await.mark_completed(order1, order2);

        // Choose a local port to execute the handshake on
        let local_port = pick_unused_port().expect("all ports used");
        let job = NetworkManagerJob::internal(NetworkManagerControlSignal::BrokerMpcNet {
            request_id,
            peer_id,
            peer_port: resp.port,
            local_port,
            local_role: ConnectionRole::Dialer,
        });
        self.network_channel.send(job).map_err(err_str!(HandshakeManagerError::SendMessage))
    }

    // -----------
    // | Helpers |
    // -----------

    /// Check a match proposal, returning a rejection reason if the proposal
    /// cannot be accepted
    async fn check_match_proposal(
        &self,
        proposal: &ProposeMatchCandidate,
    ) -> Result<Option<MatchRejectionReason>, HandshakeManagerError> {
        let ProposeMatchCandidate { peer_order: my_order, sender_order, price_vector, .. } =
            proposal;
        let peer_order_info = self.state.get_order(sender_order).await?;
        if peer_order_info.is_none() || !peer_order_info.unwrap().ready_for_match() {
            return Ok(Some(MatchRejectionReason::NoValidityProof));
        }

        // Do not accept handshakes on local orders that we don't have
        // validity proof or witness for
        if !self.state.order_ready_for_match(my_order).await? {
            return Ok(Some(MatchRejectionReason::LocalOrderNotReady));
        }

        // Verify that the proposed prices are valid by the price agreement logic
        if !self.validate_price_vector(price_vector, my_order).await? {
            return Ok(Some(MatchRejectionReason::NoPriceAgreement));
        }

        // Check if the order pair has previously been matched, if so notify the peer
        // and terminate the handshake
        let locked_handshake_cache = self.handshake_cache.read().await;
        if locked_handshake_cache.contains(*my_order, *sender_order) {
            return Ok(Some(MatchRejectionReason::Cached));
        }

        Ok(None)
    }

    /// Reject a proposed match candidate for the specified reason
    async fn reject_match_proposal(
        &self,
        request_id: Uuid,
        peer_order: OrderIdentifier,
        local_order: OrderIdentifier,
        reason: MatchRejectionReason,
    ) -> Result<HandshakeMessage, HandshakeManagerError> {
        let message = HandshakeMessage {
            request_id,
            message_type: HandshakeMessageType::Reject(RejectMatchCandidate {
                peer_id: self.state.get_peer_id().await?,
                peer_order,
                sender_order: local_order,
                reason,
            }),
        };

        Ok(message)
    }
}
