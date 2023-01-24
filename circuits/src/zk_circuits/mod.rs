//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network
pub mod valid_commitments;
pub mod valid_match_encryption;
pub mod valid_match_mpc;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

#[cfg(test)]
mod test_helpers {
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_prime_field, prime_field_to_scalar, scalar_to_prime_field,
            DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        types::{
            balance::Balance,
            fee::Fee,
            order::{Order, OrderSide},
            wallet::{Wallet, NUM_KEYS},
        },
        zk_gadgets::merkle::merkle_test::get_opening_indices,
    };

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        pub(crate) static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1, amount: 5 },
            Balance {
                mint: 2,
                amount: 10
            }
        ];
        pub(crate) static ref INITIAL_ORDERS: [Order; MAX_ORDERS] = [
            Order {
                quote_mint: 1,
                base_mint: 2,
                side: OrderSide::Buy,
                price: 5,
                amount: 1,
                timestamp: TIMESTAMP,
            },
            Order {
                quote_mint: 1,
                base_mint: 3,
                side: OrderSide::Sell,
                price: 2,
                amount: 10,
                timestamp: TIMESTAMP,
            }
        ];
        pub(crate) static ref INITIAL_FEES: [Fee; MAX_FEES] = [Fee {
            settle_key: BigUint::from(11u8),
            gas_addr: BigUint::from(1u8),
            percentage_fee: 1,
            gas_token_amount: 3,
        }];
        pub(crate) static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            fees: INITIAL_FEES.clone(),
            keys: vec![Scalar::from(1u64); NUM_KEYS].try_into().unwrap(),
            randomness: Scalar::from(42u64)
        };
    }

    // -------------
    // | Constants |
    // -------------

    /// The maximum number of balances allowed in a wallet for tests
    pub(crate) const MAX_BALANCES: usize = 2;
    /// The maximum number of orders allowed in a wallet for tests
    pub(crate) const MAX_ORDERS: usize = 2;
    /// The maximum number of fees allowed in a wallet for tests
    pub(crate) const MAX_FEES: usize = 1;
    /// The initial timestamp used in testing
    pub(crate) const TIMESTAMP: u64 = 3; // dummy value

    pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------
    /// Compute the commitment to a wallet
    pub(crate) fn compute_wallet_commitment(wallet: &SizedWallet) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());

        // Hash the balances into the state
        for balance in wallet.balances.iter() {
            hasher.absorb(&vec![balance.mint, balance.amount]);
        }

        // Hash the orders into the state
        for order in wallet.orders.iter() {
            hasher.absorb(&vec![
                order.quote_mint,
                order.base_mint,
                order.side as u64,
                order.price,
                order.amount,
            ]);
        }

        // Hash the fees into the state
        for fee in wallet.fees.iter() {
            hasher.absorb(&vec![
                biguint_to_prime_field(&fee.settle_key),
                biguint_to_prime_field(&fee.gas_addr),
            ]);

            hasher.absorb(&vec![fee.gas_token_amount, fee.percentage_fee]);
        }

        // Hash the keys into the state
        hasher.absorb(&wallet.keys.iter().map(scalar_to_prime_field).collect_vec());

        // Hash the randomness into the state
        hasher.absorb(&scalar_to_prime_field(&wallet.randomness));

        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet, create a dummy opening to a dummy root
    ///
    /// Returns a scalar and two vectors representing:
    ///     - The root of the Merkle tree
    ///     - The opening values (sister nodes)
    ///     - The opening indices (left or right)
    pub(crate) fn create_wallet_opening<R: RngCore + CryptoRng>(
        wallet: &SizedWallet,
        height: usize,
        index: usize,
        rng: &mut R,
    ) -> (Scalar, Vec<Scalar>, Vec<Scalar>) {
        // Create random sister nodes for the opening
        let random_opening = (0..height - 1).map(|_| Scalar::random(rng)).collect_vec();
        let opening_indices = get_opening_indices(index, height);

        // Compute the root of the mock Merkle tree
        let mut curr_root = compute_wallet_commitment(wallet);
        for (path_index, sister_node) in opening_indices.iter().zip(random_opening.iter()) {
            let mut sponge = PoseidonSponge::new(&default_poseidon_params());

            // Left hand child
            let left_right = if path_index.eq(&Scalar::zero()) {
                vec![curr_root, scalar_to_prime_field(sister_node)]
            } else {
                vec![scalar_to_prime_field(sister_node), curr_root]
            };

            sponge.absorb(&left_right);
            curr_root = sponge.squeeze_field_elements(1 /* num_elements */)[0];
        }

        (
            prime_field_to_scalar(&curr_root),
            random_opening,
            opening_indices,
        )
    }

    /// Given a wallet and its commitment, compute the wallet spend nullifier
    pub(crate) fn compute_wallet_spend_nullifier(
        wallet: &SizedWallet,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![commitment, scalar_to_prime_field(&wallet.randomness)]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet and its commitment, compute the wallet match nullifier
    pub(crate) fn compute_wallet_match_nullifier(
        wallet: &SizedWallet,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![
            commitment,
            scalar_to_prime_field(&(wallet.randomness + Scalar::one())),
        ]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }
}
