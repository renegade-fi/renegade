//! Defines the error type for the ExternalPriceReporter.

use std::{
    error::Error,
    fmt::{self, Display},
};

/// The core error type thrown by the ExternalPriceReporter worker.
#[derive(Clone, Debug)]
pub enum ExternalPriceReporterError {
    /// The spawning of the initial ExternalPriceReporter execution thread
    /// failed
    ManagerSetup(String),
}

impl Display for ExternalPriceReporterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for ExternalPriceReporterError {}
