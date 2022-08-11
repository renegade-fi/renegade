mod wallet_commit;

use crate::circuits::wallet_commit::{
    WalletVar
};

fn run_circuit() -> Option<()> {
    Some(())
}

#[cfg(test)]
mod tests {
    use super::run_circuit;

    #[test]
    fn test_basic() {
        assert!(run_circuit().is_none())
    }
}