//! Helpers for error handling

/// Expands a given error type to wrap a stringified version of a given error
///
/// To be used in a map_err() call
#[macro_export]
macro_rules! err_str {
    ($x:expr) => {
        |e| $x(e.to_string())
    };
}
