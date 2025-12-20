//! Mocks of various types used throughout the implementation of the MPC Network

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use ark_mpc::{
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, PartyId},
    offline_prep::PreprocessingPhase,
};
use async_trait::async_trait;

use constants::{Scalar, ScalarShare, SystemCurveGroup};
use futures::{Future, Sink, Stream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// The maximum message length in the mock network, used for debugging
pub const MAX_MESSAGE_LEN: u64 = 1_000_000;

/// An implementation of a beaver value source that returns
/// beaver triples (0, 0, 0) for party 0 and (1, 1, 1) for party 1
#[derive(Clone, Debug, Default)]
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
/// parties. We assume a = 2, b = 3 ==> c = 6. [a] = (1, 1); [b] = (3, 0) [c] =
/// (2, 4)
///
/// We also assume the MAC key is a secret sharing of 1 with each party holding
/// their own party id as a mac key share
impl PreprocessingPhase<SystemCurveGroup> for PartyIDBeaverSource {
    fn get_mac_key_share(&self) -> Scalar {
        Scalar::from(self.party_id)
    }

    // Use three for input masks as a non zero or one value
    fn next_local_input_mask(&mut self) -> (Scalar, ScalarShare) {
        let party = Scalar::from(self.party_id);
        let value = Scalar::from(3u8);

        let share = party * value;
        let mac = party * value;

        (value, ScalarShare::new(share, mac))
    }

    fn next_counterparty_input_mask(&mut self) -> ScalarShare {
        let party = Scalar::from(self.party_id);
        let value = Scalar::from(3u8) * party;
        let mac = party * value;

        ScalarShare::new(value, mac)
    }

    fn next_shared_bit(&mut self) -> ScalarShare {
        // Simply output partyID, assume partyID \in {0, 1}
        assert!(self.party_id == 0 || self.party_id == 1);
        let value = Scalar::from(self.party_id);
        ScalarShare::new(value, value)
    }

    fn next_triplet(&mut self) -> (ScalarShare, ScalarShare, ScalarShare) {
        let a = Scalar::from(2u8);
        let b = Scalar::from(3u8);
        let c = Scalar::from(6u8);

        let party_id = Scalar::from(self.party_id);
        let a_mac = party_id * a;
        let b_mac = party_id * b;
        let c_mac = party_id * c;

        let (a_share, b_share, c_share) = if self.party_id == 0 {
            (Scalar::from(1u64), Scalar::from(3u64), Scalar::from(2u64))
        } else {
            (Scalar::from(1u64), Scalar::from(0u64), Scalar::from(4u64))
        };

        (
            ScalarShare::new(a_share, a_mac),
            ScalarShare::new(b_share, b_mac),
            ScalarShare::new(c_share, c_mac),
        )
    }

    fn next_shared_inverse_pair(&mut self) -> (ScalarShare, ScalarShare) {
        (
            ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id)),
            ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id)),
        )
    }

    fn next_shared_value(&mut self) -> ScalarShare {
        ScalarShare::new(Scalar::from(self.party_id), Scalar::from(self.party_id))
    }
}

/// An unbounded duplex channel used to mock a network connection
pub struct UnboundedDuplexStream<T> {
    /// The send side of the stream
    send: UnboundedSender<T>,
    /// The receive side of the stream
    recv: UnboundedReceiver<T>,
}

impl<T> UnboundedDuplexStream<T> {
    /// Create a new pair of duplex streams
    pub fn new_duplex_pair() -> (Self, Self) {
        let (send1, recv1) = unbounded_channel();
        let (send2, recv2) = unbounded_channel();

        (Self { send: send1, recv: recv2 }, Self { send: send2, recv: recv1 })
    }

    /// Send a message on the stream
    pub fn send(&mut self, msg: T) {
        self.send.send(msg).unwrap();
    }

    /// Recv a message from the stream
    pub async fn recv(&mut self) -> T {
        self.recv.recv().await.unwrap()
    }
}

/// A dummy network implementation used for unit testing
pub struct MockNetwork {
    /// The ID of the local party
    party_id: PartyId,
    /// The underlying mock network connection
    mock_conn: UnboundedDuplexStream<NetworkOutbound<SystemCurveGroup>>,
}

impl MockNetwork {
    /// Create a new mock network from one half of a duplex stream
    pub fn new(
        party_id: PartyId,
        stream: UnboundedDuplexStream<NetworkOutbound<SystemCurveGroup>>,
    ) -> Self {
        Self { party_id, mock_conn: stream }
    }
}

#[async_trait]
impl MpcNetwork<SystemCurveGroup> for MockNetwork {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl Stream for MockNetwork {
    type Item = Result<NetworkOutbound<SystemCurveGroup>, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Box::pin(self.mock_conn.recv()).as_mut().poll(cx).map(|value| Some(Ok(value)))
    }
}

impl Sink<NetworkOutbound<SystemCurveGroup>> for MockNetwork {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: NetworkOutbound<SystemCurveGroup>,
    ) -> Result<(), Self::Error> {
        self.mock_conn.send(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
