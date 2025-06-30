//! Implements a thread-safe mapping between request IDs and channels waiting to
//! be notified of the response

use std::collections::HashMap;

use job_types::network_manager::NetworkResponseChannel;
use libp2p::request_response::RequestId;
use util::concurrency::{AsyncShared, new_async_shared};

/// Maps request IDs to channels waiting to be notified of the response
#[derive(Clone)]
pub struct ResponseWaiters {
    /// The underlying map
    map: AsyncShared<HashMap<RequestId, NetworkResponseChannel>>,
}

impl Default for ResponseWaiters {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseWaiters {
    /// Constructor
    pub fn new() -> Self {
        Self { map: new_async_shared(HashMap::new()) }
    }

    /// Get the channel for the given request ID
    pub async fn pop(&self, request_id: RequestId) -> Option<NetworkResponseChannel> {
        self.map.write().await.remove(&request_id)
    }

    /// Push a channel to wait for the response of the given request ID
    pub async fn insert(&self, request_id: RequestId, channel: NetworkResponseChannel) {
        self.map.write().await.insert(request_id, channel);
    }
}
