//! Mocks of various types used throughout the implementation of the MPC Network

use std::mem::size_of;

use async_trait::async_trait;

use mpc_stark::{
    algebra::scalar::Scalar,
    beaver::SharedValueSource,
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, PartyId},
    PARTY0,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Clone, Debug)]
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
impl SharedValueSource for PartyIDBeaverSource {
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

/// A dummy network implementation used for unit testing
pub struct MockNetwork {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: DuplexStream,
}

impl MockNetwork {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(party_id: PartyId, stream: DuplexStream) -> Self {
        Self {
            party_id,
            mock_conn: stream,
        }
    }
}

#[async_trait]
impl MpcNetwork for MockNetwork {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn send_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        let msg_bytes = serde_json::to_vec(&message)
            .map_err(|e| MpcNetworkError::SerializationError(e.to_string()))?;

        // Write the message length first
        self.mock_conn
            .write_u64(msg_bytes.len() as u64)
            .await
            .map_err(|err| MpcNetworkError::SendError(err.to_string()))?;

        // Write the byte buffer
        self.mock_conn
            .write_all(&msg_bytes)
            .await
            .map_err(|err| MpcNetworkError::SendError(err.to_string()))?;

        Ok(())
    }

    async fn receive_message(&mut self) -> Result<NetworkOutbound, MpcNetworkError> {
        // Receive the message length first
        let msg_len = self
            .mock_conn
            .read_u64()
            .await
            .map_err(|err| MpcNetworkError::RecvError(err.to_string()))?;

        let mut buf = vec![0u8; msg_len as usize];
        self.mock_conn
            .read_exact(&mut buf)
            .await
            .map_err(|err| MpcNetworkError::RecvError(err.to_string()))?;

        let msg: NetworkOutbound = serde_json::from_slice(&buf)
            .map_err(|e| MpcNetworkError::SerializationError(e.to_string()))?;
        Ok(msg)
    }

    async fn exchange_messages(
        &mut self,
        message: NetworkOutbound,
    ) -> Result<NetworkOutbound, MpcNetworkError> {
        if self.party_id() == PARTY0 {
            self.send_message(message).await?;
            self.receive_message().await
        } else {
            let res = self.receive_message().await?;
            self.send_message(message).await?;
            Ok(res)
        }
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}
