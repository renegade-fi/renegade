//! The balance type for an account
//!
//! This type wraps a DarkpoolBalance in a StateWrapper, similar to how Order
//! wraps Intent.

use std::fmt::{self, Display, Formatter};

use alloy::primitives::Address;
use circuit_types::Amount;
use darkpool_types::{balance::DarkpoolBalance, state_wrapper::StateWrapper};
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// The balance type for an account
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct Balance {
    /// The balance data wrapped in a state wrapper
    pub state_wrapper: StateWrapper<DarkpoolBalance>,
    /// The location of the balance
    pub location: BalanceLocation,
}

/// The location of a balance
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug, Hash, PartialEq, Eq)))]
pub enum BalanceLocation {
    /// An EOA balance approved to the darkpool for trading
    EOA,
    /// A balance in the darkpool Merkle state
    Darkpool,
}

impl Display for BalanceLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BalanceLocation::EOA => write!(f, "EOA"),
            BalanceLocation::Darkpool => write!(f, "Darkpool"),
        }
    }
}

impl Balance {
    /// Create a new balance from a state wrapper
    pub fn new(state_wrapper: StateWrapper<DarkpoolBalance>, location: BalanceLocation) -> Self {
        Self { state_wrapper, location }
    }

    /// Create a new EOA balance
    pub fn new_eoa(state_wrapper: StateWrapper<DarkpoolBalance>) -> Self {
        Self::new(state_wrapper, BalanceLocation::EOA)
    }

    /// Create a new darkpool balance
    pub fn new_darkpool(state_wrapper: StateWrapper<DarkpoolBalance>) -> Self {
        Self::new(state_wrapper, BalanceLocation::Darkpool)
    }

    /// Get a reference to the inner balance
    pub fn inner(&self) -> &DarkpoolBalance {
        self.state_wrapper.as_ref()
    }

    /// Get the mint address
    pub fn mint(&self) -> Address {
        self.inner().mint
    }

    /// Get the owner address
    pub fn owner(&self) -> Address {
        self.inner().owner
    }

    /// Get the amount
    pub fn amount(&self) -> Amount {
        self.inner().amount
    }

    /// Get the relayer fee balance
    pub fn relayer_fee_balance(&self) -> Amount {
        self.inner().relayer_fee_balance
    }

    /// Get the protocol fee balance
    pub fn protocol_fee_balance(&self) -> Amount {
        self.inner().protocol_fee_balance
    }

    /// Get a mutable reference to the amount
    pub fn amount_mut(&mut self) -> &mut Amount {
        &mut self.state_wrapper.inner.amount
    }

    /// Withdraw an amount from the balance
    pub fn withdraw(&mut self, amount: Amount) {
        *self.amount_mut() -= amount;
    }
}

impl From<StateWrapper<DarkpoolBalance>> for Balance {
    fn from(balance: StateWrapper<DarkpoolBalance>) -> Self {
        Self::new(balance, BalanceLocation::Darkpool)
    }
}

impl From<Balance> for DarkpoolBalance {
    fn from(balance: Balance) -> Self {
        balance.inner().clone()
    }
}

impl AsRef<DarkpoolBalance> for Balance {
    fn as_ref(&self) -> &DarkpoolBalance {
        self.inner()
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedBalance {
    /// Get the balance of the amount
    pub fn amount(&self) -> Amount {
        self.state_wrapper.inner.amount.to_native()
    }

    /// Get the amount as an archived type
    pub fn amount_archived(&self) -> <Amount as rkyv::Archive>::Archived {
        self.state_wrapper.inner.amount
    }
}

#[cfg(feature = "mocks")]
/// Mock types for balance testing
pub mod mocks {
    use super::Balance;
    use alloy::primitives::Address;
    use circuit_types::primitives::schnorr::SchnorrPublicKey;
    use constants::Scalar;
    use darkpool_types::{balance::DarkpoolBalance, state_wrapper::StateWrapper};
    use rand::{Rng, RngCore, thread_rng};

    /// Create a mock balance for testing
    pub fn mock_balance() -> Balance {
        let balance = mock_darkpool_balance();
        let mut rng = thread_rng();
        let share_stream_seed = Scalar::random(&mut rng);
        let recovery_stream_seed = Scalar::random(&mut rng);
        let state_wrapper = StateWrapper::new(balance, share_stream_seed, recovery_stream_seed);
        Balance::new_eoa(state_wrapper)
    }

    /// Create a mock balance with a specific mint
    pub fn mock_balance_with_mint(mint: Address) -> Balance {
        let mut balance = mock_darkpool_balance();
        balance.mint = mint;
        let mut rng = thread_rng();
        let share_stream_seed = Scalar::random(&mut rng);
        let recovery_stream_seed = Scalar::random(&mut rng);
        let state_wrapper = StateWrapper::new(balance, share_stream_seed, recovery_stream_seed);
        Balance::new_eoa(state_wrapper)
    }

    /// Create a mock DarkpoolBalance
    fn mock_darkpool_balance() -> DarkpoolBalance {
        let mut rng = thread_rng();
        let mut addr_bytes = [0u8; 20];
        rng.fill_bytes(&mut addr_bytes);
        let mint = Address::from(addr_bytes);
        rng.fill_bytes(&mut addr_bytes);
        let owner = Address::from(addr_bytes);
        rng.fill_bytes(&mut addr_bytes);
        let relayer_fee_recipient = Address::from(addr_bytes);
        let authority = SchnorrPublicKey::default();

        DarkpoolBalance {
            mint,
            owner,
            relayer_fee_recipient,
            authority,
            relayer_fee_balance: rng.r#gen(),
            protocol_fee_balance: rng.r#gen(),
            amount: rng.r#gen(),
        }
    }
}
