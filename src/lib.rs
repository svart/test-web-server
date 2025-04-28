use once_cell::sync::Lazy;
use rand::{Rng, thread_rng};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_BYTES_LIMIT: usize = 10_000_000;

static RANDOM_BYTES: Lazy<RandomDataBuffer> = Lazy::new(RandomDataBuffer::new);

struct RandomDataBuffer {
    data: Vec<u8>,
    current_position: Mutex<usize>,
}

impl RandomDataBuffer {
    fn new() -> Self {
        let mut rng = thread_rng();
        let data: Vec<u8> = (0..MAX_BYTES_LIMIT).map(|_| rng.r#gen()).collect();

        Self {
            data,
            current_position: Mutex::new(0),
        }
    }

    fn get_slice(&self, size: usize) -> Cow<[u8]> {
        let mut position = self.current_position.lock().unwrap();

        if *position + size <= MAX_BYTES_LIMIT {
            let slice = &self.data[*position..*position + size];

            *position = (*position + size) % MAX_BYTES_LIMIT;

            Cow::Borrowed(slice)
        } else {
            let mut result = Vec::with_capacity(size);

            let first_part_size = MAX_BYTES_LIMIT - *position;
            result.extend_from_slice(&self.data[*position..]);
            result.extend_from_slice(&self.data[..size - first_part_size]);

            *position = (*position + size) % MAX_BYTES_LIMIT;
            Cow::Owned(result)
        }
    }
}

#[derive(Debug, Default)]
pub struct RequestCounter {
    count: AtomicUsize,
}

impl RequestCounter {
    pub fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
        }
    }

    pub fn increment(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reset(&self) -> usize {
        self.count.swap(0, Ordering::Relaxed)
    }
}

pub fn rand_bytes_plain(n: usize) -> Cow<'static, [u8]> {
    let slice = RANDOM_BYTES.get_slice(n);
    slice
}

pub fn rand_bytes_sha256(n: usize) -> (Output<Sha256>, Cow<'static, [u8]>) {
    let slice = RANDOM_BYTES.get_slice(n);
    let mut hasher = Sha256::new();
    hasher.update(&slice);
    let hash = hasher.finalize();
    (hash, slice)
}

pub fn rand_bytes_crc32(n: usize) -> (u32, Cow<'static, [u8]>) {
    let slice = RANDOM_BYTES.get_slice(n);
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let cksum = crc.checksum(&slice);
    (cksum, slice)
}

pub fn rand_bytes_crc32fast(n: usize) -> (u32, Cow<'static, [u8]>) {
    let slice = RANDOM_BYTES.get_slice(n);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&slice);
    let cksum = hasher.finalize();
    (cksum, slice)
}
