//! Groups integration tests for comparators

use circuits::mpc_gadgets::comparators::{
    eq, eq_zero, greater_than, greater_than_equal, kary_or, less_than, less_than_equal,
};
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use rand::{seq::SliceRandom, thread_rng, Rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::check_equal;

/// Tests all the inequality comparators
fn test_inequalities(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 chooses a, party 1 chooses b
    // let my_random_value = if test_args.party_id == 0 {
    //     485813802
    // } else {
    //     530804745
    // }; // thread_rng().next_u64();
    // Do not use all bits to avoid overflow, for the sake of testing this is okay
    let my_random_value = test_args.borrow_fabric().party_id(); // (thread_rng().next_u32() / 4) as u64;
    let shared_a = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, my_random_value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_b = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, my_random_value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let opened_a = scalar_to_u64(
        &shared_a
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a: {:?}", err))?
            .to_scalar(),
    );
    let opened_b = scalar_to_u64(
        &shared_b
            .open_and_authenticate()
            .map_err(|err| format!("Error opening shared b: {:?}", err))?
            .to_scalar(),
    );

    // Test <
    let lt_result = less_than::<250, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a < 0: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a < 0 result: {:?}", err))?;
    let mut expected_result = (opened_a < opened_b) as u64;

    check_equal(&lt_result, expected_result)?;

    // Test <= with equal values
    let mut lte_result =
        less_than_equal::<2504, _, _>(&shared_a, &shared_a, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing a <= a: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a <= a result: {:?}", err))?;
    check_equal(&lte_result, 1)?;

    // Test <= with random values
    lte_result = less_than_equal::<250, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a <= b: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a <= b result: {:?}", err))?;
    expected_result = (opened_a <= opened_b) as u64;
    check_equal(&lte_result, expected_result)?;

    // Test >
    let gt_result = greater_than::<250, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a > b: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a > b result: {:?}", err))?;
    expected_result = (opened_a > opened_b) as u64;
    check_equal(&gt_result, expected_result)?;

    // Test >= with equal values
    let gte_result =
        greater_than_equal::<250, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing a >= b: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a >= b result: {:?}", err))?;
    expected_result = (opened_a >= opened_b) as u64;
    check_equal(&gte_result, expected_result)?;

    Ok(())
}

/// Tests the equality comparators
fn test_equalities(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // 0 == 0
    let shared_zero = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, 0u64)
        .map_err(|err| format!("Error sharing zero: {:?}", err))?;
    let mut res = eq_zero::<250, _, _>(&shared_zero, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing 0 == 0: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of 0 == 0: {:?}", err))?;

    check_equal(&res, 1)?;

    // random == 0
    let mut rng = thread_rng();
    let shared_random = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error sharing private random value: {:?}", err))?;
    res = eq_zero::<250, _, _>(&shared_random, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing random == 0: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of random == 0: {:?}", err))?;

    check_equal(&res, 0)?;

    // random_1 == random_1
    let shared_random = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error allocating shared random value: {:?}", err))?;
    res = eq::<250, _, _>(&shared_random, &shared_random, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing random_1 == random_1: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| {
            format!(
                "Error opening the result of random_1 == random_1: {:?}",
                err
            )
        })?;

    check_equal(&res, 1)?;

    // random_1 == random_2
    let shared_random1 = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error allocating private random value: {:?}", err))?;
    let shared_random2 = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error sharing private random value: {:?}", err))?;

    res = eq::<250, _, _>(
        &shared_random1,
        &shared_random2,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error computing random_1 == random_2: {:?}", err))?
    .open_and_authenticate()
    .map_err(|err| {
        format!(
            "Error opening the result of random_1 == random_2: {:?}",
            err
        )
    })?;

    check_equal(&res, 0)?;

    Ok(())
}

/// Tests the k-ary or boolean operator
fn test_kary_or(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // All zeros
    let n = 10;
    let zeros = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(0 /* owning_party */, &vec![0u64; n])
        .map_err(|err| format!("Error sharing zeros: {:?}", err))?;
    let res = kary_or(&zeros, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing OR(0, ..., 0): {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening OR(0, ..., 0) result: {:?}", err))?;

    check_equal(&res, 0u64)?;

    // A random amount of ones
    let mut rng = thread_rng();
    let mut values = (0..(rng.gen_range(1..n)))
        .map(|_| {
            test_args
                .borrow_fabric()
                .allocate_private_u64(1 /* owning_party */, 1 /* value */)
                .unwrap()
        })
        .collect::<Vec<_>>();
    values.append(
        &mut (0..n - values.len())
            .map(|_| {
                test_args
                    .borrow_fabric()
                    .allocate_private_u64(1 /* owning_party */, 0 /* value */)
                    .unwrap()
            })
            .collect::<Vec<_>>(),
    );

    // Randomly permute the array and compute the k-ary or
    values.shuffle(&mut rng);
    let res = kary_or(&values, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing random k-ary OR: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening result of random k-ary OR: {:?}", err))?;

    check_equal(&res, 1)?;

    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_inequalities",
    test_fn: test_inequalities
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_equalities",
    test_fn: test_equalities
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_kary_or",
    test_fn: test_kary_or
}));
