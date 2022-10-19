//! Groups type definitions used in integration tests

/// A format for inventorying test setup
///
/// Consumers of this package should check in integration tests
/// in the following format using the `inventory` package.
///
/// The test harness will take inventory and dispatch from there
/// at runtime
#[derive(Clone, Copy)]
pub struct IntegrationTest<FnArgs> {
    pub name: &'static str,
    pub test_fn: fn(&FnArgs) -> Result<(), String>,
}
