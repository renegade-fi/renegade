//! Defines logic for running the internal matching engine on a given order

use tracing::log;

use crate::{handshake::error::HandshakeManagerError, state::OrderIdentifier};

use super::HandshakeExecutor;

impl HandshakeExecutor {
    /// Run the internal matching engine on the given order
    pub(super) async fn run_internal_matching_engine(
        &self,
        order: OrderIdentifier,
    ) -> Result<(), HandshakeManagerError> {
        log::info!("Running internal matching engine on order {order}");
        todo!()
    }
}
