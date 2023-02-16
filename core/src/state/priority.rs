//! Groups state primitives, type definitions, and synchronization logic for
//! the state object that stores order and cluster priorities for handshakes

use std::{collections::HashMap, sync::atomic::AtomicU32};

use crate::gossip::types::ClusterId;

use super::OrderIdentifier;

/// A type alias for the abstract priority implementation
pub type Priority = AtomicU32;
/// The default priority for an order

/// Stores handshake priority information at multiple granularities; i.e.
/// cluster and order granularity
///
/// A cluster can have its priority lowered from the default for toxic behavior
/// (dropping MPCs, unreliable heartbeats, faulty proofs, etc). An order may have
/// its priority raised as a result of known IoIs on the order
#[derive(Debug)]
pub struct HandshakePriorityStore {
    /// A mapping from cluster ID to priority
    cluster_priorities: HashMap<ClusterId, Priority>,
    /// A mapping from order ID to priority
    order_priorities: HashMap<OrderIdentifier, Priority>,
}

impl HandshakePriorityStore {
    /// Create a new priority store for handshakes
    pub fn new() -> Self {
        HandshakePriorityStore {
            cluster_priorities: HashMap::new(),
            order_priorities: HashMap::new(),
        }
    }
}
