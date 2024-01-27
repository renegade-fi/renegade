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

/// A helper macro for returning early in the case that an option is `None`
/// wherein the return type is `Result<Option<T>, E>`
#[macro_export]
macro_rules! res_some {
    ($x:expr) => {
        match $x {
            Some(x) => x,
            None => return Ok(None),
        }
    };
}
