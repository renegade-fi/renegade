//! Structured logging vocabulary for the price reporter worker.
//!
//! Defines the closed set of operations the worker performs, used as the
//! `task` field in structured log records via [`util::log_task`].

use util::logging::LogTask;

/// The set of operations performed by the price reporter worker.
#[derive(Copy, Clone, Debug)]
pub enum Task {
    /// Spin-up and tear-down of a price reporter.
    ReporterLifecycle,
    /// Establishing and re-establishing exchange websocket connections.
    ExchangeConnection,
    /// Forwarding price messages over an established price stream.
    PriceStream,
    /// Fetching a single price for a pair.
    FetchPrice,
    /// Liveness checks against price feeds.
    Healthcheck,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ReporterLifecycle => "reporter-lifecycle",
            Task::ExchangeConnection => "exchange-connection",
            Task::PriceStream => "price-stream",
            Task::FetchPrice => "fetch-price",
            Task::Healthcheck => "healthcheck",
        }
    }
}
