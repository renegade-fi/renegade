//! Mocks of various types used throughout the implementation of the MPC Network

use async_trait::async_trait;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use mpc_ristretto::{beaver::SharedValueSource, error::MpcNetworkError, network::MpcNetwork};

/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Debug)]
pub struct PartyIDBeaverSource {
    /// The ID of the local party
    party_id: u64,
}

impl PartyIDBeaverSource {
    /// Create a new beaver source given the local party_id
    pub fn new(party_id: u64) -> Self {
        Self { party_id }
    }
}

/// The PartyIDBeaverSource returns beaver triplets split statically between the
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] = (2, 4)
impl SharedValueSource<Scalar> for PartyIDBeaverSource {
    fn next_shared_bit(&mut self) -> Scalar {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        Scalar::from(self.party_id)
    }

    fn next_triplet(&mut self) -> (Scalar, Scalar, Scalar) {
        if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        }
    }

    fn next_shared_inverse_pair(&mut self) -> (Scalar, Scalar) {
        (Scalar::from(self.party_id), Scalar::from(self.party_id))
    }

    fn next_shared_value(&mut self) -> Scalar {
        Scalar::from(self.party_id)
    }
}

/// Mocks out an MPC network and allows creation of mock values from the peer
#[derive(Clone, Debug, Default)]
pub struct MockMpcNet {
    /// A list of scalars to be drained when the interface expects to
    /// receive a scalar
    mock_scalars: Vec<Scalar>,
    /// A list of Ristretto points to be drained when the interface expects to
    /// receive a point
    mock_points: Vec<RistrettoPoint>,
}

impl MockMpcNet {
    /// Constructor
    pub fn new() -> Self {
        Self {
            mock_scalars: vec![],
            mock_points: vec![],
        }
    }

    /// Add scalars to the mock response buffer
    ///
    /// Subsequent calls to the MpcNetwork interface that expect a non-empty
    /// Scalar response will drain from this buffer.
    pub fn add_mock_scalars(&mut self, scalars: Vec<Scalar>) {
        self.mock_scalars.extend_from_slice(&scalars);
    }

    /// Add Ristretto points to the mock response buffer
    ///
    /// Subsequent calls to the MpcNetwork interface that expect a non-empty
    /// RistrettoPoint response will drain from this buffer
    pub fn add_mock_points(&mut self, points: Vec<RistrettoPoint>) {
        self.mock_points.extend_from_slice(&points);
    }
}

#[async_trait]
impl MpcNetwork for MockMpcNet {
    fn party_id(&self) -> u64 {
        0
    }

    async fn send_bytes(&mut self, _bytes: &[u8]) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_bytes(&mut self) -> Result<Vec<u8>, MpcNetworkError> {
        Err(MpcNetworkError::RecvError)
    }

    async fn send_scalars(&mut self, _: &[Scalar]) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_scalars(
        &mut self,
        num_scalars: usize,
    ) -> Result<Vec<Scalar>, MpcNetworkError> {
        Ok(self.mock_scalars.drain(0..num_scalars).as_slice().to_vec())
    }

    async fn broadcast_points(
        &mut self,
        points: &[RistrettoPoint],
    ) -> Result<Vec<RistrettoPoint>, MpcNetworkError> {
        Ok(self.mock_points.drain(0..points.len()).as_slice().to_vec())
    }

    async fn send_points(&mut self, _: &[RistrettoPoint]) -> Result<(), MpcNetworkError> {
        Ok(())
    }

    async fn receive_points(
        &mut self,
        num_points: usize,
    ) -> Result<Vec<RistrettoPoint>, MpcNetworkError> {
        Ok(self.mock_points.drain(0..num_points).as_slice().to_vec())
    }

    async fn broadcast_scalars(
        &mut self,
        scalars: &[Scalar],
    ) -> Result<Vec<Scalar>, MpcNetworkError> {
        Ok(self
            .mock_scalars
            .drain(0..scalars.len())
            .as_slice()
            .to_vec())
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
