use ark_ed_on_bn254;
use ark_relations::{
    r1cs::{Namespace, SynthesisError}
};
use ark_r1cs_std::{bits::uint64::UInt64, prelude::AllocVar};
use std::borrow::Borrow;

/**
 * Groups logic for arkworks gadets related to wallet commitments
 */

// The scalar field used throughout the proof system
pub type SystemField = ark_ed_on_bn254::Fr;

// Represents a wallet and its analog in the constraint system
pub struct Wallet {
    pub balances: Vec<Balance>
}

pub struct WalletVar {
    pub balances: Vec<BalancesVar>,
}

impl AllocVar<Wallet, SystemField> for WalletVar {
    // Allocates a new variable in the given CS
    fn new_variable<T: Borrow<Wallet>>(
        cs: impl Into<Namespace<SystemField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {

        // Map each balance into a constraint variable
        f().and_then(|wallet| {
            let cs = cs.into();
            let wallet: &Wallet = wallet.borrow();
            let mut balances = Vec::<BalancesVar>::new();

            for balance in wallet.balances.iter() {
                balances.push(
                    BalancesVar::new_variable(cs.clone(), || Ok(balance), mode)?
                );
            }
            Ok(Self { balances })
        }) 
    }
}

// Represents a balance tuple and its analog in the constraint system
#[derive(Clone, Debug)]
pub struct Balance {
    mint: u64,
    amount: u64
}

#[derive(Clone, Debug)]
pub struct BalancesVar {
    pub mint: UInt64<SystemField>,
    pub amount: UInt64<SystemField>
}

impl AllocVar<Balance, SystemField> for BalancesVar {
    fn new_variable<T: Borrow<Balance>>(
        cs: impl Into<Namespace<SystemField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|balance| {
            let cs = cs.into();
            let mint = UInt64::new_variable(
                cs.clone(), 
                || Ok(balance.borrow().mint), 
                mode
            )?;

            let amount = UInt64::new_variable(
                cs.clone(), 
                || Ok(balance.borrow().amount), 
                mode
            )?;

            Ok(Self { mint, amount })
        })
    }
}
