#![allow(missing_docs, clippy::missing_docs_in_private_items)]
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{Rng, thread_rng};
use state::{storage::db::DB, test_helpers::mock_db};
use types_account::account::{Account, mocks::mock_empty_account};

// -----------
// | Helpers |
// -----------

/// A table used for benchmarking
const BENCHMARK_TABLE: &str = "benchmark_table";

/// One byte
const ONE_BYTE: usize = 1;
/// One kilobyte
const ONE_KILOBYTE: usize = 1024;
/// One megabyte
const ONE_MEGABYTE: usize = 1024 * ONE_KILOBYTE;

/// Create a mock database for testing
fn benchmark_db() -> DB {
    let db = mock_db();
    db.create_table(BENCHMARK_TABLE).unwrap();

    db
}

// --------------
// | Benchmarks |
// --------------

/// A basic throughput benchmark on storage reads to random locations
pub fn bench_read_throughput(c: &mut Criterion) {
    /// The number of values to store
    const N_VALUES: usize = 1000;
    let mut rng = thread_rng();
    let db = benchmark_db();

    let mut group = c.benchmark_group("storage");
    for n_bytes in [ONE_BYTE, ONE_KILOBYTE, ONE_MEGABYTE].iter() {
        // Fill the table with `N_VALUES` values of size `n_bytes`
        for j in 0..N_VALUES {
            let key = format!("key_{j}");
            let mut val: Vec<u8> = vec![0; *n_bytes];
            rng.fill(&mut val[..]);

            db.write(BENCHMARK_TABLE, &key, &val).unwrap();
        }

        // Benchmark the read throughput of the stored value
        let id = BenchmarkId::new("read_throughput", n_bytes);
        group.throughput(Throughput::Bytes(*n_bytes as u64));
        group.bench_function(id, |b| {
            b.iter(|| {
                let random_idx = rng.gen_range(0..N_VALUES);
                let key = format!("key_{random_idx}");
                let val: Vec<u8> = db.read(BENCHMARK_TABLE, &key).unwrap().unwrap();
                black_box(val);
            })
        });
    }
}

/// A basic throughput benchmark on storage writes
pub fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage");

    let mut rng = thread_rng();
    let db = benchmark_db();

    for (i, n_bytes) in [ONE_BYTE, ONE_KILOBYTE, ONE_MEGABYTE].iter().enumerate() {
        let key = format!("key_{i}");
        let mut val = vec![0; *n_bytes];
        rng.fill(&mut val[..]);

        let id = BenchmarkId::new("write_throughput", n_bytes);
        group.throughput(Throughput::Bytes(*n_bytes as u64));
        group.bench_function(id, |b| {
            b.iter(|| {
                db.write(BENCHMARK_TABLE, &key, &val).unwrap();
            })
        });
    }
}

/// A basic throughput benchmark reading an account from storage
pub fn bench_read_account(c: &mut Criterion) {
    /// The number of accounts to store
    const N_ACCOUNTS: usize = 1000;
    let mut rng = thread_rng();

    // Add a set of accounts to the database
    let db = benchmark_db();
    let tx = db.new_write_tx().unwrap();
    let mut account_ids = Vec::new();
    for _ in 0..N_ACCOUNTS {
        let account = mock_empty_account();
        account_ids.push(account.id);
        tx.new_account(&account).unwrap();
    }
    tx.commit().unwrap();

    // Benchmark the read throughput of the stored value
    let mut group = c.benchmark_group("storage");

    group.throughput(Throughput::Elements(1));
    group.bench_function("read_account", |b| {
        b.iter(|| {
            let random_idx = rng.gen_range(0..N_ACCOUNTS);
            let account_id = account_ids[random_idx];

            let tx = db.new_read_tx().unwrap();
            let account: Account = tx.get_account(&account_id).unwrap().unwrap();
            tx.commit().unwrap();

            black_box(account);
        })
    });
}

/// A basic throughput benchmark writing an account to storage
pub fn bench_write_account(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage");
    let db = benchmark_db();
    let account = mock_empty_account();

    group.throughput(Throughput::Elements(1));
    group.bench_function("write_account", |b| {
        b.iter(|| {
            let tx = db.new_write_tx().unwrap();
            tx.new_account(&account).unwrap();
            tx.commit().unwrap();

            black_box(());
        })
    });
}

criterion_group!(
    name = storage;
    config = Criterion::default();
    targets = bench_read_throughput, bench_write_throughput, bench_read_account, bench_write_account
);
criterion_main!(storage);
