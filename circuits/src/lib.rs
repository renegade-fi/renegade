use curve25519_dalek::scalar::Scalar;
use errors::MpcError;
use mpc::SharedFabric;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};

pub mod constants;
pub mod errors;
pub mod mpc;
pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod types;

/// Defines functionality to allocate a value within an MPC network
pub trait Allocate<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    type Output;
    /// Allocates the raw type in the network as a shared value
    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::Output, MpcError>;
}
