use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group};
use std::hint::black_box;
use std::time::Duration;
#[cfg(feature = "crc32")]
use test_web_server::rand_bytes_crc32;
use test_web_server::rand_bytes_plain;
#[cfg(feature = "sha256")]
use test_web_server::rand_bytes_sha256;

fn compare_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("Compare response body checksum algorithms");
    group.sampling_mode(SamplingMode::Flat);
    for request_size in [
        1, 64, 4096, 512_000, 1_024_000, 4_096_000, 8_192_000, 10_000_000,
    ] {
        group.bench_with_input(
            BenchmarkId::new("Plain", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_plain(black_box(size))),
        );

        #[cfg(feature = "sha256")]
        group.bench_with_input(
            BenchmarkId::new("SHA256", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_sha256(black_box(size))),
        );

        #[cfg(feature = "crc32")]
        group.bench_with_input(
            BenchmarkId::new("CRC32", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_crc32(black_box(size))),
        );
    }
}

criterion_group!(name = rand_bytes;
    config = Criterion::default().measurement_time(Duration::from_secs(30)).warm_up_time(Duration::from_secs(5)).sample_size(100);
    targets = compare_algorithms);
