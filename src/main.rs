use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::{extract::Path, http::StatusCode, response::Html, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use tokio::time::{interval, Duration};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: std::net::IpAddr,

    #[arg(short, long, default_value = "3000")]
    port: u16,
}

const MAX_BYTES_LIMIT: usize = 10_000_000;

static RANDOM_BYTES: Lazy<RandomDataBuffer> = Lazy::new(RandomDataBuffer::new);

struct RandomDataBuffer {
    data: Vec<u8>,
    current_position: Mutex<usize>,
}

impl RandomDataBuffer {
    fn new() -> Self {
        let mut rng = thread_rng();
        let data: Vec<u8> = (0..MAX_BYTES_LIMIT).map(|_| rng.gen()).collect();

        Self {
            data,
            current_position: Mutex::new(0),
        }
    }

    fn get_slice(&self, size: usize) -> Cow<[u8]> {
        let mut position = self.current_position.lock().unwrap();

        if *position + size < MAX_BYTES_LIMIT {
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

struct RequestCounter {
    count: AtomicUsize,
}

impl RequestCounter {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
        }
    }

    fn increment(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn reset(&self) -> usize {
        self.count.swap(0, Ordering::Relaxed)
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let counter = Arc::new(RequestCounter::new());
    let counter_clone = counter.clone();

    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1));
        let mut last_count: usize = 0;
        let mut consecutive_zeros = 0;

        loop {
            interval.tick().await;
            let count = counter_clone.reset();

            if count > 0 || (count == 0 && last_count > 0) {
                info!("{} rps", count);
                consecutive_zeros = 0;
            } else if count == 0 && consecutive_zeros == 0 {
                info!("0 rps");
                consecutive_zeros += 1;
            }
            last_count = count;
        }
    });

    // Build application with necessary routes
    let app = Router::new()
        .route("/", get(root))
        .route(
            "/bytes/:n",
            get(move |path| rand_bytes(path, counter.clone())),
        )
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::new(cli.address, cli.port);
    info!("listenning on {}", addr);

    let listener = TcpListener::bind(addr).unwrap();

    let config = RustlsConfig::from_pem_file("keys/server.crt", "keys/server.key")
        .await
        .unwrap();

    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> Html<&'static str> {
    Html(
        "<h1>Welcome to Random Bytes Server.</h1>
          <p>Use the /bytes/N endpoint to get N random bytes.</p>",
    )
}

async fn rand_bytes<'a>(Path(n): Path<usize>, counter: Arc<RequestCounter>) -> impl IntoResponse {
    counter.increment();

    if n > MAX_BYTES_LIMIT {
        return Err(StatusCode::BAD_REQUEST);
    }
    let slice = RANDOM_BYTES.get_slice(n);
    let mut hasher = Sha256::new();
    hasher.update(&slice);
    let hash = hasher.finalize();
    let hex_hash = base16ct::lower::encode_string(&hash);
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&hex_hash) {
        Ok(value) => {
            headers.insert("sha256", value);
        }
        Err(e) => {
            warn!("err{e:?}");
        }
    };
    Ok((headers, slice))
}
