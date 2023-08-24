//! Defines assertion helpers that match the signature of the `renegade` integration tests

/// Assert that a boolean value is true, return an error otherwise
#[macro_export]
macro_rules! assert_true {
    ($x:expr) => {
        if $x {
            Ok(())
        } else {
            Err(eyre::eyre!(
                "Expected `{} == true`, got `false`",
                stringify!($x)
            ))
        }
    };
}

/// Assert that two values are equal, return an error otherwise
#[macro_export]
macro_rules! assert_eq {
    ($x:expr, $y:expr) => {
        if $x == $y {
            Ok(())
        } else {
            Err(eyre::eyre!(
                "Expected `{} == {}`, got `{:?} == {:?}`",
                stringify!($x),
                stringify!($y),
                $x,
                $y
            ))
        }
    };
}
