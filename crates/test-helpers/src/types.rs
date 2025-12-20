//! Groups type definitions used in integration tests
#![allow(clippy::crate_in_macro_def)]

use std::{
    fmt::{self, Display},
    pin::Pin,
    str::FromStr,
};

use eyre::Result;
use futures::Future;

/// Macro to create an integration test
#[macro_export]
macro_rules! integration_test {
    ($test_fn:ident) => {
        inventory::submit!(crate::TestWrapper(test_helpers::types::IntegrationTest {
            name: std::concat! {std::module_path!(), "::", stringify!($test_fn)},
            test_fn: test_helpers::types::IntegrationTestFn::SynchronousFn($test_fn),
        }));
    };
}

/// Macro to create an asynchronous integration test
#[macro_export]
macro_rules! integration_test_async {
    ($test_fn:ident) => {
        inventory::submit!(crate::TestWrapper(test_helpers::types::IntegrationTest {
            name: std::concat! {std::module_path!(), "::", stringify!($test_fn)},
            test_fn: test_helpers::types::IntegrationTestFn::AsynchronousFn(move |args| {
                std::boxed::Box::pin($test_fn(args))
            }),
        }));
    };
}
pub use integration_test;

/// A format for inventorying test setup
///
/// Consumers of this package should check in integration tests
/// in the following format using the `inventory` package.
///
/// The test harness will take inventory and dispatch from there
/// at runtime
pub struct IntegrationTest<FnArgs> {
    /// The semantic of the test, displayed in the test logs
    pub name: &'static str,
    /// The callback used by the harness to run the test
    pub test_fn: IntegrationTestFn<FnArgs>,
}

/// A type for encapsulating both synchronous and asynchronous integration tests
/// within a single test harness
#[allow(clippy::type_complexity)]
pub enum IntegrationTestFn<FnArgs> {
    /// A synchronous test, i.e. not `async`
    SynchronousFn(fn(FnArgs) -> Result<()>),
    /// An asynchronous test
    AsynchronousFn(fn(FnArgs) -> Pin<Box<dyn Future<Output = Result<()>>>>),
}

/// The verbosity at which to run a test
#[derive(Debug, Clone, Copy, Default)]
pub enum TestVerbosity {
    /// No output
    Quiet,
    /// Only the test harness will output logs
    #[default]
    Default,
    /// Full verbosity, logging enabled
    Full,
}

impl Display for TestVerbosity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for TestVerbosity {
    type Err = String;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quiet" => Ok(Self::Quiet),
            "default" => Ok(Self::Default),
            "full" => Ok(Self::Full),
            _ => Err(format!("invalid verbosity level: {}", s)),
        }
    }
}
