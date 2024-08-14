//! Defines a network mock that introduces a constant connection delay

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use ark_mpc::{
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, PartyId},
};
use async_trait::async_trait;
use constants::SystemCurveGroup;
use futures::{ready, FutureExt, Sink, Stream};

use super::mocks::UnboundedDuplexStream;

/// A type alias for a network message with a send timestamp attached
type NetworkOutboundWithTimestamp = (Instant, NetworkOutbound<SystemCurveGroup>);

/// The representation of a delayed network connection
pub struct MockNetworkWithDelay {
    /// The party ID of the local party
    party_id: PartyId,
    /// The underlying stream that mocks a real connection
    ///
    /// Contains a send timestamp as well as the actual message
    mock_conn: UnboundedDuplexStream<NetworkOutboundWithTimestamp>,
    /// The buffered message on the receive side
    recv_buffer: Option<NetworkOutboundWithTimestamp>,
    /// The delay to introduce on each message
    delay: Duration,
    /// The current timer allocated for the delay, must be held so that it
    /// remains registered with the runtime's timer driver
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl MockNetworkWithDelay {
    /// Constructor
    pub fn new(
        party_id: PartyId,
        stream: UnboundedDuplexStream<NetworkOutboundWithTimestamp>,
        delay: Duration,
    ) -> Self {
        Self { party_id, mock_conn: stream, recv_buffer: None, delay, timer: None }
    }

    /// Register a timer to awake after the delay
    ///
    /// This requires both creating a `tokio::time::Sleep` instance and then
    /// polling it so that the timer is registered with the driver
    #[allow(unused_must_use)]
    pub fn register_timer(mut self: Pin<&mut Self>, duration: Duration, cx: &mut Context<'_>) {
        assert!(!duration.is_zero(), "timer duration already elapsed");

        // Create a timer and poll it
        let mut pinned_timer = Box::pin(tokio::time::sleep(duration));
        pinned_timer.as_mut().poll(cx);

        // Store the pinned timer so that it remains registered with the runtime
        self.timer.replace(pinned_timer);
    }
}

#[async_trait]
impl MpcNetwork<SystemCurveGroup> for MockNetworkWithDelay {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn close(&mut self) -> Result<(), MpcNetworkError> {
        Ok(())
    }
}

impl Stream for MockNetworkWithDelay {
    type Item = Result<NetworkOutbound<SystemCurveGroup>, MpcNetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check the buffer to see if a message is ready to be received
        let (instant, message) =
            if let Some((send_time, message)) = self.as_mut().recv_buffer.take() {
                (send_time, message)
            } else {
                ready!(Box::pin(self.mock_conn.recv()).poll_unpin(cx))
            };

        // If the delay between the send time and now has elapsed, return the message
        // Otherwise, buffer the message and register a timer to wake up after the delay
        let duration_since_send = Instant::now() - instant;
        if duration_since_send >= self.delay {
            Poll::Ready(Some(Ok(message)))
        } else {
            self.recv_buffer = Some((instant, message));

            let timer_delay = self.delay - duration_since_send;
            self.register_timer(timer_delay, cx);
            Poll::Pending
        }
    }
}

/// Send side directly calls out to the underlying mock connection
impl Sink<NetworkOutbound<SystemCurveGroup>> for MockNetworkWithDelay {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: NetworkOutbound<SystemCurveGroup>,
    ) -> Result<(), Self::Error> {
        let send_time = Instant::now();
        self.mock_conn.send((send_time, item));
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ark_mpc::{
        network::{NetworkOutbound, NetworkPayload},
        PARTY0,
    };
    use constants::Scalar;
    use futures::{SinkExt, StreamExt};
    use renegade_crypto::fields::scalar_to_u64;
    use util::get_current_time_millis;

    use crate::mpc_network::{mock_with_delay::MockNetworkWithDelay, mocks::UnboundedDuplexStream};

    /// Test that the delay is accurate
    #[tokio::test]
    async fn test_delay() {
        const DELAY_MS: u64 = 100;
        const N_SENDS: u64 = 1000;
        const DELAY_TOLERANCE_MS: u64 = 10;

        // Broker a connection
        let (party0_stream, party1_stream) = UnboundedDuplexStream::new_duplex_pair();

        // Spawn a sender and receiver separately
        let sender = tokio::spawn(async move {
            let mut conn =
                MockNetworkWithDelay::new(PARTY0, party0_stream, Duration::from_millis(DELAY_MS));

            // Send the current timestamp as a `Scalar`
            for _ in 0..N_SENDS {
                let now = get_current_time_millis();
                let msg = NetworkOutbound {
                    result_id: 0,
                    payload: NetworkPayload::Scalar(Scalar::from(now)),
                };

                conn.send(msg).await.unwrap();
            }
        });

        let receiver = tokio::spawn({
            async move {
                let mut conn = MockNetworkWithDelay::new(
                    PARTY0,
                    party1_stream,
                    Duration::from_millis(DELAY_MS),
                );

                // Receive each payload and measure the delay
                for _ in 0..N_SENDS {
                    let msg = conn.next().await.unwrap().unwrap();
                    if let NetworkPayload::Scalar(send_ts) = msg.payload {
                        let recv_ts = get_current_time_millis();
                        let delay = recv_ts - scalar_to_u64(&send_ts);

                        // Check that the delay is within `DELAY_TOLERANCE` of the expected delay
                        let delay_diff = delay - DELAY_MS;
                        if delay_diff > DELAY_TOLERANCE_MS {
                            return false;
                        }
                    } else {
                        unreachable!("unexpected payload type");
                    }
                }

                true
            }
        });

        let (sender_result, receiver_result) = tokio::join!(sender, receiver);
        sender_result.unwrap();
        let res = receiver_result.unwrap();
        assert!(res);
    }
}
