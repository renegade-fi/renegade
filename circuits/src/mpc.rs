//! Groups logic around MPC structure
use std::{
    cell::{Ref, RefCell},
    net::SocketAddr,
    rc::Rc,
};

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    beaver::SharedValueSource,
    fabric::AuthenticatedMpcFabric,
    network::{MpcNetwork, QuicTwoPartyNet},
    BeaverSource,
};

use crate::errors::MpcError;

/**
 * Types
 */

/// Type alias that curries one generic out of the concern of this implementation
#[allow(type_alias_bounds)]
pub type MpcFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> =
    AuthenticatedMpcFabric<N, S>;
/// A shared fabric for multi-owner mutability
#[derive(Debug)]
pub struct SharedFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    pub Rc<RefCell<MpcFabric<N, S>>>,
);

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharedFabric<N, S> {
    /// Wrap an existing fabric in a shared mutibility struct
    pub fn new(fabric: AuthenticatedMpcFabric<N, S>) -> Self {
        Self(Rc::new(RefCell::new(fabric)))
    }

    /// Borrow the shared MPC fabric as an immutable reference
    pub fn borrow_fabric(&self) -> Ref<MpcFabric<N, S>> {
        self.0.as_ref().borrow()
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for SharedFabric<N, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/**
 * Generic, module level helpers
 */

/// Create a new MPC fabric from a high level beaver source
pub fn new_mpc_fabric<S: SharedValueSource<Scalar>>(
    party_id: u64,
    peer_addr: SocketAddr,
    beaver_source: BeaverSource<S>,
) -> Result<AuthenticatedMpcFabric<QuicTwoPartyNet, S>, MpcError> {
    let local_addr: SocketAddr = "192.168.0.1"
        .parse()
        .map_err(|_| MpcError::SetupError("invalid peer addr".to_string()))?;

    let fabric = AuthenticatedMpcFabric::new(local_addr, peer_addr, beaver_source, party_id)
        .map_err(|_| MpcError::SetupError("error connecting to peer".to_string()))?;

    Ok(fabric)
}
