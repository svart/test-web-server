use criterion::criterion_main;

mod benchmarks;

criterion_main! {
    benchmarks::response_generator::rand_bytes,
}
