//! Groups type definitions used in integration tests
#![allow(clippy::crate_in_macro_def)]

use std::pin::Pin;

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
