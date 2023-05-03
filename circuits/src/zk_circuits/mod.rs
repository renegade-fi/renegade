//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network
pub mod valid_commitments;
pub mod valid_match_mpc;
pub mod valid_reblind;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

#[cfg(test)]
mod test_helpers {
    use std::iter::from_fn;

    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_scalar, prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::{
        native_helpers::compute_poseidon_hash,
        types::{
            balance::{Balance, BalanceSecretShare},
            fee::{Fee, FeeSecretShare},
            keychain::{PublicKeyChain, PublicKeyChainSecretShare, NUM_KEYS},
            order::{Order, OrderSecretShare, OrderSide},
            wallet::{Wallet, WalletSecretShare},
        },
        zk_gadgets::{
            fixed_point::FixedPoint,
            merkle::MerkleOpening,
            nonnative::{
                biguint_to_scalar_words, NonNativeElementSecretShare, TWO_TO_256_FIELD_MOD,
            },
        },
    };

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        // The key data for the wallet, note that only the identification keys are currently
        // computed correctly
        pub(crate) static ref PRIVATE_KEYS: Vec<Scalar> = vec![Scalar::one(); NUM_KEYS];
        pub(crate) static ref PUBLIC_KEYS: PublicKeyChain = PublicKeyChain {
            pk_root: BigUint::from(1u8).into(),
            pk_match: compute_poseidon_hash(&[PRIVATE_KEYS[1]]).into(),
        };
        pub(crate) static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1u8.into(), amount: 5 },
            Balance {
                mint: 2u8.into(),
                amount: 10
            }
        ];
        pub(crate) static ref INITIAL_ORDERS: [Order; MAX_ORDERS] = [
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: OrderSide::Buy,
                price: FixedPoint::from(5.),
                amount: 1,
                timestamp: TIMESTAMP,
            },
            Order {
                quote_mint: 1u8.into(),
                base_mint: 3u8.into(),
                side: OrderSide::Sell,
                price: FixedPoint::from(2.),
                amount: 10,
                timestamp: TIMESTAMP,
            }
        ];
        pub(crate) static ref INITIAL_FEES: [Fee; MAX_FEES] = [Fee {
            settle_key: BigUint::from(11u8),
            gas_addr: BigUint::from(1u8),
            percentage_fee: FixedPoint::from(0.01),
            gas_token_amount: 3,
        }];
        pub(crate) static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            fees: INITIAL_FEES.clone(),
            keys: PUBLIC_KEYS.clone(),
            blinder: Scalar::from(42u64)
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
    pub type SizedWalletShare = WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Reblind a wallet given its secret shares
    ///
    /// Returns the reblinded private and public shares
    pub(crate) fn reblind_wallet(
        private_secret_shares: SizedWalletShare,
        wallet: &SizedWallet,
    ) -> (SizedWalletShare, SizedWalletShare) {
        // Sample new wallet blinders from the `blinder` CSPRNG
        // See the comments in `valid_reblind.rs` for an explanation of the two CSPRNGs
        let mut blinder_samples =
            evaluate_hash_chain(private_secret_shares.blinder, 2 /* length */);
        let mut blinder_drain = blinder_samples.drain(..);
        let new_blinder = blinder_drain.next().unwrap();
        let new_blinder_private_share = blinder_drain.next().unwrap();

        // Sample new secret shares for the wallet
        let shares_serialized: Vec<Scalar> = private_secret_shares.into();
        let serialized_len = shares_serialized.len();
        let secret_shares =
            evaluate_hash_chain(shares_serialized[serialized_len - 2], serialized_len - 1);

        create_wallet_shares_with_randomness(
            wallet,
            new_blinder,
            new_blinder_private_share,
            secret_shares,
        )
    }

    /// Compute a chained Poseidon hash of the given length from the given seed
    pub(crate) fn evaluate_hash_chain(seed: Scalar, length: usize) -> Vec<Scalar> {
        let mut seed = scalar_to_prime_field(&seed);
        let mut res = Vec::with_capacity(length);

        let poseidon_config = default_poseidon_params();
        for _ in 0..length {
            // New hasher every time to reset the hash state, Arkworks sponges don't natively
            // support resets, so we pay the small re-initialization overhead
            let mut hasher = PoseidonSponge::new(&poseidon_config);
            hasher.absorb(&seed);
            seed = hasher.squeeze_field_elements(1 /* num_elements */)[0];

            res.push(prime_field_to_scalar(&seed));
        }

        res
    }

    /// Construct secret shares of a wallet for testing
    pub(crate) fn create_wallet_shares(
        wallet: &SizedWallet,
    ) -> (SizedWalletShare, SizedWalletShare) {
        // Sample a random secret share for the blinder
        let mut rng = OsRng {};
        let blinder_share = Scalar::random(&mut rng);

        create_wallet_shares_with_randomness(
            wallet,
            wallet.blinder,
            blinder_share,
            from_fn(|| Some(Scalar::random(&mut rng))),
        )
    }

    /// Construct public shares of a wallet given the private shares and blinder
    ///
    /// The return type is a tuple containing the private and public shares. Note
    /// that the private shares returned are exactly those passed in
    pub(crate) fn create_wallet_shares_from_private(
        wallet: &SizedWallet,
        private_shares: &SizedWalletShare,
        blinder: Scalar,
    ) -> (SizedWalletShare, SizedWalletShare) {
        // Serialize the wallet's private shares and use this as the secret share stream
        let private_shares_ser: Vec<Scalar> = private_shares.clone().into();
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            private_shares.blinder,
            private_shares_ser,
        )
    }

    /// Create a secret sharing of a wallet given the secret shares and blinders
    fn create_wallet_shares_with_randomness<T>(
        wallet: &SizedWallet,
        blinder: Scalar,
        private_blinder_share: Scalar,
        secret_shares: T,
    ) -> (SizedWalletShare, SizedWalletShare)
    where
        T: IntoIterator<Item = Scalar>,
    {
        // Cast to iter and create a shorthand notation
        let mut share_iter = secret_shares.into_iter();
        macro_rules! next_share {
            () => {
                share_iter.next().unwrap()
            };
        }

        // Secret share the balances
        let mut balances1 = Vec::with_capacity(MAX_BALANCES);
        let mut balances2 = Vec::with_capacity(MAX_BALANCES);
        for balance in wallet.balances.iter() {
            let mint_share = next_share!();
            let amount_share = next_share!();
            balances1.push(BalanceSecretShare {
                mint: mint_share,
                amount: amount_share,
            });

            balances2.push(BalanceSecretShare {
                mint: biguint_to_scalar(&balance.mint) - mint_share,
                amount: Scalar::from(balance.amount) - amount_share,
            });
        }

        // Secret share the orders
        let mut orders1 = Vec::with_capacity(MAX_ORDERS);
        let mut orders2 = Vec::with_capacity(MAX_ORDERS);
        for order in wallet.orders.iter() {
            let quote_share = next_share!();
            let base_share = next_share!();
            let side_share = next_share!();
            let price_share = next_share!();
            let amount_share = next_share!();
            let timestamp_share = next_share!();

            orders1.push(OrderSecretShare {
                quote_mint: quote_share,
                base_mint: base_share,
                side: side_share,
                price: price_share,
                amount: amount_share,
                timestamp: timestamp_share,
            });

            orders2.push(OrderSecretShare {
                quote_mint: biguint_to_scalar(&order.quote_mint) - quote_share,
                base_mint: biguint_to_scalar(&order.base_mint) - base_share,
                side: Scalar::from(order.side) - side_share,
                price: order.price.repr - price_share,
                amount: Scalar::from(order.amount) - amount_share,
                timestamp: Scalar::from(order.timestamp) - timestamp_share,
            });
        }

        // Secret share the fees
        let mut fees1 = Vec::with_capacity(MAX_FEES);
        let mut fees2 = Vec::with_capacity(MAX_FEES);
        for fee in wallet.fees.iter() {
            let settle_key_share = next_share!();
            let gas_addr_share = next_share!();
            let gas_amount_share = next_share!();
            let percentage_share = next_share!();

            fees1.push(FeeSecretShare {
                settle_key: settle_key_share,
                gas_addr: gas_addr_share,
                gas_token_amount: gas_amount_share,
                percentage_fee: percentage_share,
            });

            fees2.push(FeeSecretShare {
                settle_key: biguint_to_scalar(&fee.settle_key) - settle_key_share,
                gas_addr: biguint_to_scalar(&fee.gas_addr) - gas_addr_share,
                gas_token_amount: Scalar::from(fee.gas_token_amount) - gas_amount_share,
                percentage_fee: fee.percentage_fee.repr - percentage_share,
            })
        }

        // Secret share the keychain
        let root_key_words = biguint_to_scalar_words(wallet.keys.pk_root.0.clone());
        let root_shares1 = (0..root_key_words.len())
            .map(|_| next_share!())
            .collect_vec();
        let root_shares2 = root_key_words
            .iter()
            .zip(root_shares1.iter())
            .map(|(w1, w2)| w1 - w2)
            .collect_vec();

        let match_share = next_share!();

        let keychain1 = PublicKeyChainSecretShare {
            pk_root: NonNativeElementSecretShare {
                words: root_shares1,
                field_mod: TWO_TO_256_FIELD_MOD.clone(),
            },
            pk_match: match_share,
        };
        let keychain2 = PublicKeyChainSecretShare {
            pk_root: NonNativeElementSecretShare {
                words: root_shares2,
                field_mod: TWO_TO_256_FIELD_MOD.clone(),
            },
            pk_match: wallet.keys.pk_match.0 - match_share,
        };

        // Construct the secret shares of the wallet
        let wallet1 = SizedWalletShare {
            balances: balances1.try_into().unwrap(),
            orders: orders1.try_into().unwrap(),
            fees: fees1.try_into().unwrap(),
            keys: keychain1,
            blinder: private_blinder_share,
        };
        let mut wallet2 = SizedWalletShare {
            balances: balances2.try_into().unwrap(),
            orders: orders2.try_into().unwrap(),
            fees: fees2.try_into().unwrap(),
            keys: keychain2,
            blinder: blinder - private_blinder_share,
        };

        // Blind the public shares
        wallet2.blind(blinder);

        (wallet1, wallet2)
    }

    /// Create a multi-item opening in a Merkle tree, do so by constructing the Merkle tree
    /// from the given items, padded with zeros
    ///
    /// The return type is structured as a tuple with the following elements in order:
    ///     - root: The root of the Merkle tree
    ///     - openings: A vector of opening vectors; the sister nodes hashed with the Merkle path
    ///     - opening_indices: A vector of opening index vectors; the left/right booleans for the path
    pub(crate) fn create_multi_opening<R: RngCore + CryptoRng>(
        items: &[Scalar],
        height: usize,
        rng: &mut R,
    ) -> (Scalar, Vec<MerkleOpening>) {
        let tree_capacity = 2usize.pow(height as u32);
        assert!(
            items.len() < tree_capacity,
            "tree capacity exceeded by seed items"
        );

        // Pad the inputs up to the tree capacity
        let mut merkle_leaves = items.to_vec();
        merkle_leaves.append(&mut vec![Scalar::random(rng); tree_capacity - items.len()]);

        // The return variables
        let mut openings = vec![Vec::new(); items.len()];
        let mut opening_indices = vec![Vec::new(); items.len()];

        // Compute the openings and root of the tree
        let mut curr_internal_nodes = merkle_leaves.clone();
        let mut curr_indices = (0..items.len()).collect_vec();

        // Loop over the levels of the tree, construct the openings as we go
        while curr_internal_nodes.len() > 1 {
            // The curr_indices represents the indices of each opening's path in the current height
            // compute a sister node for each at the given height and add it to the opening for that
            // path.
            for (i, ind) in curr_indices.iter().enumerate() {
                // Compute the opening index (i.e. whether this is a left or right child)
                let path_index = ind % 2;
                // Compute the sister node for the given index at the given height
                let sister_node =
                    curr_internal_nodes[if path_index == 0 { ind + 1 } else { ind - 1 }];

                openings[i].push(sister_node);
                opening_indices[i].push(Scalar::from(path_index as u8));
            }

            // Hash together each left and right pair to get the internal node values at the next height
            let mut next_internal_nodes = Vec::with_capacity(curr_internal_nodes.len() / 2);
            for left_right in curr_internal_nodes
                .chunks(2 /* size */)
                .map(|chunk| chunk.iter().map(scalar_to_prime_field).collect_vec())
            {
                let mut sponge = PoseidonSponge::new(&default_poseidon_params());
                sponge.absorb(&left_right);

                let squeezed: DalekRistrettoField =
                    sponge.squeeze_field_elements(1 /* num_elements */)[0];
                next_internal_nodes.push(prime_field_to_scalar(&squeezed));
            }

            // Update the curr_indices vector to be the index of the parent node in the Merkle tree height
            // above the current height. This is simply \floor(index / 2)
            curr_indices = curr_indices.iter().map(|index| index >> 2).collect_vec();
            curr_internal_nodes = next_internal_nodes;
        }

        let merkle_root = curr_internal_nodes[0];

        // Reformat the openings and indices into the `MerkleOpening` type
        let merkle_openings = openings
            .into_iter()
            .zip(opening_indices.into_iter())
            .map(|(elems, indices)| MerkleOpening { elems, indices })
            .collect_vec();
        (merkle_root, merkle_openings)
    }

    // ---------------------
    // | Helper Validation |
    // ---------------------

    /// Verify that the wallet shares helper correctly splits and recombines
    #[test]
    fn test_split_wallet_into_shares() {
        // Split into secret shares
        let wallet = INITIAL_WALLET.clone();
        let (private_share, mut public_share) = create_wallet_shares(&wallet);

        // Unblind the public shares, recover from shares
        public_share.unblind(wallet.blinder);
        let recovered_wallet = private_share + public_share;

        assert_eq!(wallet, recovered_wallet);
    }

    /// Verify that reblinding a wallet creates valid secret shares of the underlying wallet
    #[test]
    fn test_reblind_wallet() {
        let mut wallet = INITIAL_WALLET.clone();
        let (private_share, _) = create_wallet_shares(&wallet);

        // Reblind the shares
        let (reblinded_private_shares, mut reblinded_public_shares) =
            reblind_wallet(private_share, &wallet);

        // Unblind the public shares, recover from shares
        let recovered_blinder = reblinded_public_shares.blinder + reblinded_private_shares.blinder;
        reblinded_public_shares.unblind(recovered_blinder);
        let recovered_wallet = reblinded_private_shares + reblinded_public_shares;

        wallet.blinder = recovered_blinder;
        assert_eq!(wallet, recovered_wallet);
    }
}
