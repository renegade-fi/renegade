//! Helpers for `task-driver` integration tests

use common::types::wallet_mocks::mock_empty_wallet;
use external_api::types::Wallet as ApiWallet;
use system_bus::SystemBus;
use task_driver::driver::TaskDriver;

// ---------
// | Mocks |
// ---------

/// Create a new mock `TaskDriver`
pub fn new_mock_task_driver() -> TaskDriver {
    let bus = SystemBus::new();
    TaskDriver::new(bus)
}

// --------------
// | Dummy Data |
// --------------

/// Create a new, empty wallet
pub fn create_empty_api_wallet() -> ApiWallet {
    // Create the wallet secret shares let circuit_wallet = SizedWallet {
    let state_wallet = mock_empty_wallet();
    ApiWallet::from(state_wallet)
}
