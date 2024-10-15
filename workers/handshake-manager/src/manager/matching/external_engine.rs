//! The matching engine for external matches
//!
//! An external match is one that occurs between an internal party (with state
//! allocated in the darkpool) and an external party (with no state in the
//! darkpool).
//!
//! The external matching engine is responsible for matching an external order
//! against all known internal order

use common::types::wallet::Order;

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

impl HandshakeExecutor {
    /// Execute an external match
    pub async fn run_external_matching_engine(
        &self,
        order: Order,
    ) -> Result<(), HandshakeManagerError> {
        todo!()
    }
}
