//! The handshake scheduler, periodically enqueues handshakes to be executed by
//! the local node

use std::time::Duration;

use common::types::CancelChannel;
use constants::in_bootstrap_mode;
use job_types::handshake_manager::{HandshakeExecutionJob, HandshakeManagerQueue};
use state::State;
use tracing::info;
use util::{err_str, runtime::sleep_forever_async};

use crate::error::HandshakeManagerError;

/// How frequently a new handshake is initiated from the local peer
pub(super) const HANDSHAKE_INTERVAL_MS: u64 = 2_000; // 2 seconds
/// Number of nanoseconds in a millisecond, for convenience
const NANOS_PER_MILLI: u64 = 1_000_000;
/// Whether MPC matches are disabled
const DISABLE_MPC_MATCHES: bool = true;

/// Implements a timer that periodically enqueues jobs to the threadpool that
/// tell the manager to send outbound handshake requests
#[derive(Clone)]
pub struct HandshakeScheduler {
    /// The UnboundedSender to enqueue jobs on
    job_sender: HandshakeManagerQueue,
    /// A copy of the relayer-global state
    state: State,
    /// The cancel channel to receive cancel signals on
    cancel: CancelChannel,
}

impl HandshakeScheduler {
    /// Construct a new timer
    pub fn new(job_sender: HandshakeManagerQueue, state: State, cancel: CancelChannel) -> Self {
        Self { job_sender, state, cancel }
    }

    /// The execution loop of the timer, periodically enqueues handshake jobs
    pub async fn execution_loop(mut self) -> HandshakeManagerError {
        // TODO(@joeykraut): Enable multi-cluster support
        if in_bootstrap_mode() || DISABLE_MPC_MATCHES {
            sleep_forever_async().await;
        }

        let interval_seconds = HANDSHAKE_INTERVAL_MS / 1000;
        let interval_nanos = (HANDSHAKE_INTERVAL_MS % 1000 * NANOS_PER_MILLI) as u32;

        let refresh_interval = Duration::new(interval_seconds, interval_nanos);

        loop {
            tokio::select! {
                // Enqueue handshakes periodically according to a timer
                _ = tokio::time::sleep(refresh_interval) => {
                    // Enqueue a job to handshake with the randomly selected peer
                    if let Some(order) = self.state.choose_handshake_order().await.ok().flatten() {
                        if let Err(e) = self
                            .job_sender
                            .send(HandshakeExecutionJob::PerformHandshake { order })
                            .map_err(err_str!(HandshakeManagerError::SendMessage))
                        {
                            return e;
                        }
                    }
                },

                _ = self.cancel.changed() => {
                    info!("Handshake manager cancelled, winding down");
                    return HandshakeManagerError::Cancelled("received cancel signal".to_string());
                }
            }
        }
    }
}
