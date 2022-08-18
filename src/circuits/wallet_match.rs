use ark_ed_on_bn254;
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;
use ark_r1cs_std::{
    bits::{
        boolean::Boolean,
        uint64::UInt64,
        uint8::UInt8
    },
    R1CSVar, ToBitsGadget, prelude::EqGadget
};
use std::{marker::PhantomData, borrow::Borrow};

use crate::circuits::{
    constants::{MAX_BALANCES, MAX_ORDERS},
    gadgets::{
        GreaterThanEqGadget,
        MaskGadget,
        MinGadget
    },
    types::{
        OrderSide,
        WalletVar,
    }
};


/**
 * Groups together logic for computing matches between wallets
 */

/**
 * Constraint system variables
 */

// The result of a matches operation and its constraint system analog
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub matches1: Vec<Match>,
    pub matches2: Vec<Match>
}

#[derive(Clone, Debug)]
pub struct MatchResultVariable<F: PrimeField> {
    pub matches1: Vec<MatchVariable<F>>,
    pub matches2: Vec<MatchVariable<F>>
}

impl<F: PrimeField> MatchResultVariable<F> {
    pub fn new() -> Self {
        Self { matches1: Vec::new(), matches2: Vec::new() }
    } 
}

impl<F: PrimeField> R1CSVar<F> for MatchResultVariable<F> {
    type Value = MatchResult;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.matches1[0].cs()
    } 

    fn is_constant(&self) -> bool {
        self.matches1[0].is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let matches1 = self.matches1
            .iter()
            .map(|match_var| match_var.value())
            .collect::<Result<Vec<Match>, SynthesisError>>()?;
        
        let matches2 = self.matches2
            .iter()
            .map(|match_var| match_var.value())
            .collect::<Result<Vec<Match>, SynthesisError>>()?;
        
        Ok ( MatchResult { matches1, matches2 } )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    mint: u64,
    amount: u64,
    side: OrderSide
}

#[derive(Debug, Clone)]
pub struct MatchVariable<F: PrimeField> {
    pub mint: UInt64<F>,
    pub amount: UInt64<F>,
    pub side: UInt8<F>
}

impl<F: PrimeField> R1CSVar<F> for MatchVariable<F> {
    type Value = Match;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.mint.cs()
    }

    fn is_constant(&self) -> bool {
        self.mint.is_constant()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(
            Match {
                mint: self.mint.value()?,
                amount: self.amount.value()?,
                side: match self.side.value()? {
                    0 => { Ok(OrderSide::Buy) },
                    1 => { Ok(OrderSide::Sell) },
                    _ => { Err(SynthesisError::Unsatisfiable) }
                }?
            }
        )
    }
}

/**
 * Gadgets
 */

pub struct OrderOverlapGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> OrderOverlapGadget<F> {
    // Returns side1 * price1 >= side2 * price2
    pub fn is_overlapping(
        side1: &UInt8<F>,
        price1: &UInt64<F>,
        side2: &UInt8<F>,
        price2: &UInt64<F>
    ) -> Result<Boolean<F>, SynthesisError> {
        // Convert to Fp elements
        let side1_fp = Boolean::le_bits_to_fp_var(&side1.to_bits_le()?)?;
        let price1_fp = Boolean::le_bits_to_fp_var(&price1.to_bits_le())?;
        let side2_fp = Boolean::le_bits_to_fp_var(&side2.to_bits_le()?)?;
        let price2_fp = Boolean::le_bits_to_fp_var(&price2.to_bits_le())?;

        // side_2 * price_1 >= side_2 * price_2
        let check1 = GreaterThanEqGadget::greater_than(
            side2_fp.clone() * price1_fp.clone(),
            side2_fp.clone() * price2_fp.clone()
        )?;

        // side_1 * price_2 >= side_1 * price_1
        let check2 = GreaterThanEqGadget::greater_than(
            side1_fp.clone() * price2_fp.clone(),
            side1_fp.clone() * price1_fp.clone()
        )?;

        check1.and(&check2)
    }
}


pub struct MatchGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> MatchGadget<F> {
    pub fn compute_matches(
        wallet1: &WalletVar<F>,
        wallet2: &WalletVar<F>
    ) -> Result<MatchResultVariable<F>, SynthesisError> {
        let mut result = MatchResultVariable::<F>::new(); 

        for i in 0..MAX_ORDERS {
            for j in 0..MAX_ORDERS {
                let order1 = wallet1.orders[i].borrow();
                let order2 = wallet2.orders[j].borrow();

                let quote_mints_equal = order1.quote_mint.is_eq(&order2.quote_mint)?;
                let base_mints_equal = order1.base_mint.is_eq(&order2.base_mint)?;

                // Check that counterparties are on opposite sides of the market
                let opposite_sides = order1.side
                    .xor(&order2.side)?
                    .is_eq(&UInt8::constant(1))?;

                // Checks that the price of the seller is <= the price of the buyer
                let price_overlap = OrderOverlapGadget::is_overlapping(
                    &order1.side, 
                    &order1.price, 
                    &order2.side, 
                    &order2.price
                )?;

                // Aggregate all checks together
                let aggregated_checks = quote_mints_equal
                    .and(&base_mints_equal)?
                    .and(&opposite_sides)?
                    .and(&price_overlap)?;
                
                // Find the execution price (midpoint) and mask it with the checks
                // (price1 + price2) / 2
                // Rotate right to emulate a shift right
                // then xor with 1 << 63 to mask the top bit
                let execution_price = UInt64::addmany(
                    &[order1.price.clone(), order2.price.clone()]
                )?
                    .rotr(1) 
                    .xor(&UInt64::<F>::constant(1 << 63))?;
                
                let base_swapped = MinGadget::min_uint64(order1.amount.clone(), order2.amount.clone())?;

                // Compute the amount of quote token swapped
                // Convert to field element then back to int
                let base_swapped_fp = Boolean::le_bits_to_fp_var(&base_swapped.to_bits_le())?;
                let execution_price_fp = Boolean::le_bits_to_fp_var(&execution_price.to_bits_le())?;
                
                let quote_swapped_fp = base_swapped_fp * execution_price_fp;
                let quote_swapped = UInt64::from_bits_le(&quote_swapped_fp.to_bits_le()?[..64]);

                // Mask output if the checks failed
                let quote_mint_masked = MaskGadget::mask_uint64(&order1.quote_mint, &aggregated_checks)?;
                let base_mint_masked = MaskGadget::mask_uint64(&order1.base_mint, &aggregated_checks)?;

                let base_swapped_masked = MaskGadget::mask_uint64(&base_swapped, &aggregated_checks)?;
                let quote_swapped_masked = MaskGadget::mask_uint64(&quote_swapped, &aggregated_checks)?;

                let side1_masked = MaskGadget::mask_uint8(&order1.side, &aggregated_checks)?;
                let side2_masked = MaskGadget::mask_uint8(&order2.side, &aggregated_checks)?;
                
                // For each party; add a match for the delta in quote token and the delta in base token
                // Instead of doing 1 - side; we simply use the other party's side as we have constrained them to be opposite
                result.matches1.push(
                    MatchVariable { 
                        mint: quote_mint_masked.clone(), 
                        amount: quote_swapped_masked.clone(), 
                        side: side2_masked.clone()
                    }
                );

                result.matches1.push(
                    MatchVariable { 
                        mint: base_mint_masked.clone(),
                        amount: base_swapped_masked.clone(),
                        side: side1_masked.clone()
                    }
                );

                result.matches2.push(
                    MatchVariable { 
                        mint: quote_mint_masked, 
                        amount: quote_swapped_masked,
                        side: side1_masked
                    }
                );

                result.matches2.push(
                    MatchVariable { 
                        mint: base_mint_masked,
                        amount: base_swapped_masked, 
                        side: side2_masked 
                    }
                );
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod overlap_test {
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_r1cs_std::{
        prelude::{AllocVar, EqGadget, Boolean}, 
        uint8::UInt8, 
        uint64::UInt64
    };
    use crate::circuits::SystemField;

    use super::{OrderOverlapGadget};

    type OverlapGadget = OrderOverlapGadget<SystemField>;

    fn setup_prices<F: PrimeField>(
        buy_price: u64, 
        sell_price: u64,
        cs: ConstraintSystemRef<F>
    ) -> (UInt8<F>, UInt64<F>, UInt8<F>, UInt64<F>) {
        // Buy side
        let side1_var = UInt8::new_witness(
            ark_relations::ns!(cs, "side1"), || Ok(0)  
        ).unwrap();
        let price1_var = UInt64::new_witness(
            ark_relations::ns!(cs, "price1"), || Ok(buy_price)
        ).unwrap();

        // Sell side
        let side2_var = UInt8::new_witness(
            ark_relations::ns!(cs, "side2"), || Ok(1)
        ).unwrap();
        let price2_var = UInt64::new_witness(
            ark_relations::ns!(cs, "price2"), || Ok(sell_price)
        ).unwrap();

        (side1_var, price1_var, side2_var, price2_var)
    }

    #[test]
    fn test_overlap_gadget_no_overlap() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            100 /* buy_price */, 200 /* sell_price */, cs.clone(),
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap())
    }

    #[test]
    fn test_overlap_gadget_with_overlap() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            200 /* buy_price */, 100 /* sell_price */, cs.clone()
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        println!("Which unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        assert!(cs.is_satisfied().unwrap())
    }

    #[test]
    fn test_overlap_prices_equal() {
        let cs = ConstraintSystem::<SystemField>::new_ref();
        let (side1_var, price1_var, side2_var, price2_var) = setup_prices(
            100 /* buy_price */, 100 /* sell_price */, cs.clone()
        );

        let result_var = OverlapGadget::is_overlapping(
            &side1_var, &price1_var, &side2_var, &price2_var
        ).unwrap();

        result_var.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap())
    }
}

#[cfg(test)]
mod match_test {
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::circuits::{types::{Order, Wallet}, wallet_match::MatchResult, SystemField};
    use super::{Match, MatchGadget, OrderSide, WalletVar};

    fn has_nonzero_match(matches_list: &Vec<Match>) -> bool {
        matches_list.iter()
            .any(|match_res| {
                match_res.amount != 0 || match_res.mint != 0 || match_res.side == OrderSide::Sell // Sell side is 1
            })
    }

    #[test]
    // Tests that no matches result from orders that overlap but have
    // different mints
    fn test_match_different_mints() {
        // Build the wallets
        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 10, amount: 1, side: OrderSide::Buy }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 3, quote_mint: 4, price: 10, amount: 1, side: OrderSide::Sell }
            ]
        };

        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        // Both matches lists should be all zeroed
        assert!(res.matches1.len() > 0);
        assert!(res.matches2.len() > 0);
        assert!(!has_nonzero_match(&res.matches1));
        assert!(!has_nonzero_match(&res.matches2));
    }

    #[test]
    // Tests that no matches result from orders on the same side of a pair
    // even when prices align
    fn test_match_same_side() {
        // Build the wallets
        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 10, amount: 1, side: OrderSide::Buy }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 10, amount: 1, side: OrderSide::Buy }
            ]
        };

        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        // Check that both matches lists are zeroed 
        assert!(res.matches1.len() > 0);
        assert!(res.matches2.len() > 0);
        assert!(!has_nonzero_match(&res.matches1));
        assert!(!has_nonzero_match(&res.matches2));
    }

    #[test]
    // Tests the case in which the order prices are not overlapping
    fn test_match_no_overlap() {
        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 20, amount: 1, side: OrderSide::Sell }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint: 1, quote_mint: 2, price: 10, amount: 1, side: OrderSide::Buy }
            ]
        };

        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res1 = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        assert!(res1.matches1.len() > 0);
        assert!(res1.matches2.len() > 0);
        assert!(!has_nonzero_match(&res1.matches1));
        assert!(!has_nonzero_match(&res1.matches2));

        // Flip the wallets to ensure the arguments commute
        let res2 = MatchGadget::compute_matches(&wallet2_var, &wallet1_var)
            .unwrap()
            .value()
            .unwrap();
        
        assert!(res2.matches1.len() > 0);
        assert!(res2.matches2.len() > 0);
        assert!(!has_nonzero_match(&res2.matches1));
        assert!(!has_nonzero_match(&res2.matches2));
    }

    #[test]
    // Tests a correct match to ensure that the match is done correctly
    fn test_match_correct_match() {
        let base_mint = 1;
        let quote_mint = 2;

        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 10, amount: 2, side: OrderSide::Sell }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 20, amount: 3, side: OrderSide::Buy }
            ]
        };
        
        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        assert!(has_nonzero_match(&res.matches1));
        assert!(has_nonzero_match(&res.matches2));
        
        // Sort by mint
        let mut matches1 = res.matches1
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();
        matches1.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        let mut matches2 = res.matches2
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();

        matches2.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        // wallet 1 is selling quote currency, wallet 2 is buying quote currency
        assert!(matches1[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Sell }));
        assert!(matches1[1].eq(&Match { mint: quote_mint, amount: 30, side: OrderSide::Buy }));

        assert!(matches2[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Buy }));
        assert!(matches2[1].eq(&Match { mint: quote_mint, amount: 30, side: OrderSide::Sell }));

        // Swap arguments to ensure the circuit commutes
        let res2 = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        assert!(has_nonzero_match(&res2.matches1));
        assert!(has_nonzero_match(&res2.matches2));
        
        // filter out null matches (i.e. mint 0) and sort by mint
        let mut matches1 = res2.matches1
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();
        matches1.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        let mut matches2 = res2.matches2
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();
        matches2.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        // wallet 1 is selling quote currency, wallet 2 is buying quote currency
        assert!(matches1[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Sell }));
        assert!(matches1[1].eq(&Match { mint: quote_mint, amount: 30, side: OrderSide::Buy }));

        assert!(matches2[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Buy }));
        assert!(matches2[1].eq(&Match { mint: quote_mint, amount: 30, side: OrderSide::Sell }));
    }

    #[test]
    fn test_match_same_price() {
        let base_mint = 1;
        let quote_mint = 2;

        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 10, amount: 2, side: OrderSide::Sell }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 10, amount: 3, side: OrderSide::Buy }
            ]
        };
        
        // Build the constraint system and variables
        let cs = ConstraintSystem::<SystemField>::new_ref();

        let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(wallet1)).unwrap();
        let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(wallet2)).unwrap();

        let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
            .unwrap()
            .value()
            .unwrap();
        
        assert!(has_nonzero_match(&res.matches1));
        assert!(has_nonzero_match(&res.matches2));
        
        // Sort by mint
        let mut matches1 = res.matches1
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();
        matches1.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        let mut matches2 = res.matches2
            .iter()
            .filter(|match_res| match_res.mint != 0)
            .collect::<Vec<&Match>>();
        matches2.sort_by(|a, b| a.mint.partial_cmp(&b.mint).unwrap());

        // wallet 1 is selling quote currency, wallet 2 is buying quote currency
        assert!(matches1[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Sell }));
        assert!(matches1[1].eq(&Match { mint: quote_mint, amount: 20, side: OrderSide::Buy }));

        assert!(matches2[0].eq(&Match { mint: base_mint, amount: 2, side: OrderSide::Buy }));
        assert!(matches2[1].eq(&Match { mint: quote_mint, amount: 20, side: OrderSide::Sell }));
    }

}

#[cfg(test)]
mod proof_test {
    use ark_bn254::Bn254;
    use ark_ff::{PrimeField};
    use ark_groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};
    use ark_r1cs_std::{prelude::{AllocVar, EqGadget, Boolean}, uint64::UInt64};
    use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
    use rand::rngs::OsRng;
    use std::marker::PhantomData;

    use crate::circuits::types::{Wallet, Order, OrderSide, WalletVar};
    use super::MatchGadget;

    #[derive(Clone)]
    struct DummyCircuit<F: PrimeField> {
        wallet1: Wallet,
        wallet2: Wallet,
        _phantom: PhantomData<F>
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(
            self, 
            cs: ark_relations::r1cs::ConstraintSystemRef<F>
        ) -> Result<(), SynthesisError> {
            let wallet1_var = WalletVar::new_witness(cs.clone(), || Ok(&self.wallet1)).unwrap();
            let wallet2_var = WalletVar::new_witness(cs.clone(), || Ok(&self.wallet2)).unwrap();

            let res = MatchGadget::compute_matches(&wallet1_var, &wallet2_var)
                .unwrap();
            
            res.matches1[0].amount.is_eq(&UInt64::constant(20))
                .unwrap()
                .enforce_equal(&Boolean::TRUE)
                .unwrap();
    
            Ok(())
        }
    }

    #[test]
    fn test_prove_wallet() {
        let base_mint = 1;
        let quote_mint = 2;

        let wallet1 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 10, amount: 2, side: OrderSide::Sell }
            ]
        };

        let wallet2 = Wallet {
            balances: vec![],
            orders: vec![
                Order { base_mint, quote_mint, price: 10, amount: 3, side: OrderSide::Buy }
            ]
        };
        
        // Build the constraint system and variables
        let circuit = DummyCircuit { wallet1, wallet2, _phantom: PhantomData {} };

        // Build the proving and verifying keys
        let mut rng = OsRng{};
        let proving_key = generate_random_parameters::<
            Bn254, _, _
        >(circuit.clone(), &mut rng).unwrap();
        let verifying_key = prepare_verifying_key(&proving_key.vk);

        // Prove and verify
        let proof = create_random_proof(circuit, &proving_key, &mut rng).unwrap();

        let verification_result = verify_proof(&verifying_key, &proof, &Vec::new()[..])
            .unwrap();

        assert!(verification_result);
    }
}