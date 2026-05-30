//! The closed vocabulary of logging tasks performed by the API server crate.
//!
//! Each variant names an operation the API server performs; the kebab-cased
//! string forms are what `[task]`-prefixed greps and `@task:X` Datadog
//! aggregations key off of. See [`util::logging`] for the envelope and the
//! [`util::log_task!`] macro that consumes these.

use util::logging::LogTask;

/// The closed vocabulary of operations the API server performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Registering a route on the API server's router.
    RegisterRoute,
    /// Refreshing the token remapping from the configured repository.
    RefreshTokenMapping,
    /// Refreshing the match fees from the darkpool contract.
    RefreshMatchFees,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::RegisterRoute => "register-route",
            Task::RefreshTokenMapping => "refresh-token-mapping",
            Task::RefreshMatchFees => "refresh-match-fees",
        }
    }
}
