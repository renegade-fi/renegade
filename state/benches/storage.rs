#![allow(missing_docs, clippy::missing_docs_in_private_items)]
use common::types::{wallet::Wallet, wallet_mocks::mock_empty_wallet};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{thread_rng, Rng};
use state::{storage::db::DB, test_helpers::mock_db};

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

/// A basic throughput benchmark reading a wallet from storage
pub fn bench_read_wallet(c: &mut Criterion) {
    /// The number of wallets to store
    const N_WALLETS: usize = 1000;
    let mut rng = thread_rng();

    // Add a set of wallets to the database
    let db = benchmark_db();
    let tx = db.new_write_tx().unwrap();
    let mut wallet_ids = Vec::new();
    for _ in 0..N_WALLETS {
        let wallet = mock_empty_wallet();
        wallet_ids.push(wallet.wallet_id);
        tx.write_wallet(&wallet).unwrap();
    }
    tx.commit().unwrap();

    // Benchmark the read throughput of the stored value
    let mut group = c.benchmark_group("storage");

    group.throughput(Throughput::Elements(1));
    group.bench_function("read_wallet", |b| {
        b.iter(|| {
            let random_idx = rng.gen_range(0..N_WALLETS);
            let wallet_id = wallet_ids[random_idx];

            let tx = db.new_read_tx().unwrap();
            let wallet: Wallet = tx.get_wallet(&wallet_id).unwrap().unwrap();
            tx.commit().unwrap();

            black_box(wallet);
        })
    });
}

/// A basic throughput benchmark writing a wallet to storage
pub fn bench_write_wallet(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage");
    let db = benchmark_db();
    let wallet = mock_empty_wallet();

    group.throughput(Throughput::Elements(1));
    group.bench_function("write_wallet", |b| {
        b.iter(|| {
            let tx = db.new_write_tx().unwrap();
            tx.write_wallet(&wallet).unwrap();
            tx.commit().unwrap();

            black_box(());
        })
    });
}

criterion_group!(
    name = storage;
    config = Criterion::default();
    targets = bench_read_throughput, bench_write_throughput, bench_read_wallet, bench_write_wallet
);
criterion_main!(storage);
