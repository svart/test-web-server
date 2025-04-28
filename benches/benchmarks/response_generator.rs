use criterion::{BenchmarkId, Criterion, SamplingMode, black_box, criterion_group};
use std::time::Duration;
use test_web_server::{
    rand_bytes_crc32, rand_bytes_crc32fast, rand_bytes_plain, rand_bytes_sha256,
};

fn compare_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare rand_bytes");
    group.sampling_mode(SamplingMode::Flat);
    for request_size in [
        1, 64, 4096, 512_000, 1_024_000, 4_096_000, 8_192_000, 10_000_000,
    ] {
        group.bench_with_input(
            BenchmarkId::new("Plain", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_plain(black_box(size))),
        );

        group.bench_with_input(
            BenchmarkId::new("SHA256", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_sha256(black_box(size))),
        );

        group.bench_with_input(
            BenchmarkId::new("CRC_32_ISCSI", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_crc32(black_box(size))),
        );

        group.bench_with_input(
            BenchmarkId::new("crc32fast", request_size),
            &request_size,
            move |b, &size| b.iter(|| rand_bytes_crc32fast(black_box(size))),
        );
    }
}

criterion_group!(name = rand_bytes;
    config = Criterion::default().measurement_time(Duration::from_secs(30)).warm_up_time(Duration::from_secs(5)).sample_size(100);
    targets = compare_algorithms);
