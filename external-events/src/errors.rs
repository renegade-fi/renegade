use std::error::Error;
use std::fmt;
use std::fmt::Display;

#[derive(Clone, Debug)]
pub enum ReporterError {
    ConnectionFailure,
    // InvalidMessage,
    // NoDataReported,
}

impl Error for ReporterError {}
impl Display for ReporterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            ReporterError::ConnectionFailure => "Failed to connect to the remote websocket",
            // ReporterError::InvalidMessage => "Remote message was incorrectly formatted",
            // ReporterError::NoDataReported => "The PriceReporter has not yet collected any data",
        };
        write!(f, "{}", display_string)
    }
}
