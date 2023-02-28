//! Defines the core implementation of the on-chain event listener

use crossbeam::channel::Receiver;

/// The configuration passed to the listener upon startup
#[derive(Debug, Clone)]
pub struct OnChainEventListenerConfig {
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: Receiver<()>,
}

/// The worker responsible for listening for on-chain events, translating them to jobs for
/// other workers, and forwarding these jobs to the relevant workers
#[derive(Debug)]
pub struct OnChainEventListener {
    /// The config passed to the listener at startup
    #[allow(unused)]
    pub(super) config: OnChainEventListenerConfig,
}
