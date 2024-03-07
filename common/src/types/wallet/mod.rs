//! Wallet type and methods on the wallet
//!
//! Separated out to aid discoverability on implementations

mod balances;
pub mod derivation;
mod keychain;
mod r#match;
#[cfg(feature = "mocks")]
pub mod mocks;
mod orders;
mod shares;
mod types;

pub use types::*;

// ----------------
// | Wallet Tests |
// ----------------

#[cfg(test)]
mod test {
    use circuit_types::balance::Balance;
    use constants::{MAX_BALANCES, MAX_ORDERS};
    use num_bigint::BigUint;
    use rand::{distributions::uniform::SampleRange, thread_rng};
    use uuid::Uuid;

    use crate::types::wallet::mocks::{mock_empty_wallet, mock_order};

    /// Tests adding a balance to an empty wallet
    #[test]
    fn test_add_balance_append() {
        let mut wallet = mock_empty_wallet();
        let balance1 = Balance::new_from_mint_and_amount(BigUint::from(1u8), 10);
        let balance2 = Balance::new_from_mint_and_amount(BigUint::from(2u8), 10);
        wallet.add_balance(balance1.clone()).unwrap();
        wallet.add_balance(balance2.clone()).unwrap();

        assert_eq!(wallet.balances.len(), 2);
        assert_eq!(wallet.balances.index_of(&balance2.mint), Some(1));
    }

    /// Tests adding a balance when one already exists in the wallet
    #[test]
    fn test_add_balance_existing() {
        let mut wallet = mock_empty_wallet();
        let balance1 = Balance::new_from_mint_and_amount(BigUint::from(1u8), 10);
        let balance2 = Balance::new_from_mint_and_amount(BigUint::from(1u8), 10);
        wallet.add_balance(balance1.clone()).unwrap();
        wallet.add_balance(balance2.clone()).unwrap();

        assert_eq!(wallet.balances.len(), 1);
        assert_eq!(wallet.balances.index_of(&balance1.mint), Some(0));
        assert_eq!(wallet.balances.get(&balance1.mint).unwrap().amount, 20);
    }

    /// Tests adding a balance that overrides a zero'd balance
    #[test]
    fn test_add_balance_overwrite() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for i in 0..MAX_BALANCES {
            let balance = Balance::new_from_mint_and_amount(BigUint::from(i), 10);
            wallet.add_balance(balance).unwrap();
        }

        // Zero a random balance
        let mut rng = thread_rng();
        let idx = (0..MAX_BALANCES).sample_single(&mut rng);
        wallet.balances.get_index_mut(idx).unwrap().amount = 0;

        // Add a new balance
        let balance = Balance::new_from_mint_and_amount(BigUint::from(42u8), 10);
        wallet.add_balance(balance.clone()).unwrap();

        // Check that the balance overrode the correct idx
        assert_eq!(wallet.balances.index_of(&balance.mint), Some(idx));
    }

    /// Tests adding a balance when the wallet is full
    #[test]
    #[should_panic(expected = "balances full")]
    fn test_add_balance_full() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for i in 0..MAX_BALANCES {
            let balance = Balance::new_from_mint_and_amount(BigUint::from(i), 10);
            wallet.add_balance(balance).unwrap();
        }

        // Attempt to add another balance
        let balance = Balance::new_from_mint_and_amount(BigUint::from(42u8), 10);
        wallet.add_balance(balance).unwrap();
    }

    /// Tests adding an order that appends to the wallet
    #[test]
    fn test_add_order_append() {
        let mut wallet = mock_empty_wallet();

        // Add two orders to the wallet
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let order1 = mock_order();
        let order2 = mock_order();
        wallet.add_order(id1, order1).unwrap();
        wallet.add_order(id2, order2).unwrap();

        // Check that the orders were added
        assert_eq!(wallet.orders.len(), 2);
        assert_eq!(wallet.orders.index_of(&id1), Some(0));
        assert_eq!(wallet.orders.index_of(&id2), Some(1));
    }

    /// Tests adding an order that overwrites a default order
    #[test]
    fn test_add_order_overwrite() {
        let mut wallet = mock_empty_wallet();

        // Fill the orders with default orders
        for _ in 0..MAX_ORDERS {
            let id = Uuid::new_v4();
            let order = mock_order();
            wallet.add_order(id, order).unwrap();
        }

        // Zero a random order
        let mut rng = thread_rng();
        let idx = (0..MAX_ORDERS).sample_single(&mut rng);
        wallet.orders.get_index_mut(idx).unwrap().amount = 0;

        // Add a new order
        let id = Uuid::new_v4();
        let order = mock_order();
        wallet.add_order(id, order).unwrap();

        // Check that the order overrode the correct idx
        assert_eq!(wallet.orders.index_of(&id), Some(idx));
    }

    /// Tests adding an order when the wallet is full
    #[test]
    #[should_panic(expected = "orders full")]
    fn test_add_order_full() {
        let mut wallet = mock_empty_wallet();

        // Fill the wallet
        for _ in 0..MAX_ORDERS {
            let id = Uuid::new_v4();
            let order = mock_order();
            wallet.add_order(id, order).unwrap();
        }

        // Attempt to add another order
        let id = Uuid::new_v4();
        let order = mock_order();
        wallet.add_order(id, order).unwrap();
    }
}
