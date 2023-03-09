//! Groups state primitives, type definitions, and synchronization logic for
//! the state object that stores order and cluster priorities for handshakes

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
    },
};
use tokio::sync::RwLockReadGuard;

use crate::gossip::types::ClusterId;

use super::{new_async_shared, AsyncShared, OrderIdentifier};

/// The error emitted when an order's priority lock is poisoned
const ERR_ORDER_PRIORITY_POISONED: &str = "order priority lock poisoned";

/// The default priority for a cluster
const CLUSTER_DEFAULT_PRIORITY: u32 = 1;
/// The default priority for an order
const ORDER_DEFAULT_PRIORITY: u32 = 1;

/// A type alias for the abstract priority implementation
pub type ClusterPriority = AtomicU32;
/// A type that represents the priority for an order, including its cluster
/// priority
#[derive(Clone, Debug)]
pub struct OrderPriority {
    /// The priority of the cluster that the order is managed by
    cluster_priority: u32,
    /// The priority of the order itself
    order_priority: u32,
}

impl Default for OrderPriority {
    fn default() -> Self {
        OrderPriority {
            cluster_priority: CLUSTER_DEFAULT_PRIORITY,
            order_priority: ORDER_DEFAULT_PRIORITY,
        }
    }
}

impl OrderPriority {
    /// Compute the effective scheduling priority for an order
    pub fn get_effective_priority(&self) -> u32 {
        self.cluster_priority * self.order_priority
    }
}

/// Stores handshake priority information at multiple granularities; i.e.
/// cluster and order granularity
///
/// A cluster can have its priority lowered from the default for toxic behavior
/// (dropping MPCs, unreliable heartbeats, faulty proofs, etc). An order may have
/// its priority raised as a result of known IoIs on the order
#[derive(Debug)]
pub struct HandshakePriorityStore {
    /// A mapping from cluster ID to priority
    cluster_priorities: HashMap<ClusterId, ClusterPriority>,
    /// A mapping from order ID to priority
    order_priorities: HashMap<OrderIdentifier, AsyncShared<OrderPriority>>,
}

impl HandshakePriorityStore {
    /// Create a new priority store for handshakes
    pub fn new() -> Self {
        HandshakePriorityStore {
            cluster_priorities: HashMap::new(),
            order_priorities: HashMap::new(),
        }
    }

    // -----------
    // | Locking |
    // -----------

    /// Acquire a read lock on an order's priority
    pub async fn read_order_priority(
        &self,
        order_id: &OrderIdentifier,
    ) -> Option<RwLockReadGuard<OrderPriority>> {
        Some(self.order_priorities.get(order_id)?.read().await)
    }

    // -----------
    // | Getters |
    // -----------

    /// Read an order's priority
    pub async fn get_order_priority(&self, order_id: &OrderIdentifier) -> OrderPriority {
        self.read_order_priority(order_id)
            .await
            .map(|order| order.clone())
            .unwrap_or_default()
    }

    /// Read a cluster's priority, returns default if not indexed
    pub fn get_cluster_priority(&self, cluster_id: &ClusterId) -> u32 {
        self.cluster_priorities
            .get(cluster_id)
            .map(|priority| priority.load(Ordering::Relaxed))
            .unwrap_or(CLUSTER_DEFAULT_PRIORITY)
    }

    // -----------
    // | Setters |
    // -----------

    /// Add a new order to the priority list
    pub fn new_order(&mut self, order_id: OrderIdentifier, cluster_id: ClusterId) {
        let cluster_priority = self.get_cluster_priority(&cluster_id);
        self.order_priorities.insert(
            order_id,
            new_async_shared(OrderPriority {
                cluster_priority,
                order_priority: ORDER_DEFAULT_PRIORITY,
            }),
        );
    }

    /// Remove the order from the priority list
    pub fn remove_order(&mut self, order_id: &OrderIdentifier) {
        self.order_priorities.remove(order_id);
    }
}
