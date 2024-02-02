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

/// Expands a given error to format the string with the given format string and
/// args
///
/// The error should come last in the format string
#[macro_export]
macro_rules! raw_err_str {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        |e| format!($fmt $(, $($arg)*)?, e)
    };
}
