use std::{net::SocketAddr, sync::Arc};

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, response::Html, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, ValueEnum};
use rustls::{ServerConfig, pki_types::CertificateDer};
use std::net::TcpListener;
use test_web_server::{MAX_BYTES_LIMIT, RequestCounter};
use tokio::time::{Duration, interval};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, ValueEnum)]
enum HttpVersion {
    HTTP1,
    HTTP2,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: std::net::IpAddr,

    #[arg(short, long, default_value = "3000")]
    port: u16,

    #[arg(long, default_value = "http2")]
    http_version: HttpVersion,
}

fn random_body_response(Path(n): Path<usize>, counter: Arc<RequestCounter>) -> impl IntoResponse {
    counter.increment();

    if n > MAX_BYTES_LIMIT {
        return Err(StatusCode::BAD_REQUEST);
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "sha256_body")] {
            use test_web_server::rand_bytes_sha256;
            use axum::http::{HeaderMap, HeaderValue};
            use tracing::warn;

            let (hash, slice) = rand_bytes_sha256(n);
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
        } else {
            use test_web_server::rand_bytes_plain;
            let response = rand_bytes_plain(n);
            Ok(response)
        }
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

    // Set a process wide default crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider as the default");

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
            get(async move |path| random_body_response(path, counter.clone())),
        )
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::new(cli.address, cli.port);
    info!("listenning on {}", addr);

    let listener = TcpListener::bind(addr).unwrap();

    let config = build_rustls_config(cli.http_version);

    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn build_rustls_config(http_version: HttpVersion) -> RustlsConfig {
    let cert = std::fs::read("keys/server.crt").expect("Failed to read cert file");
    let key = std::fs::read("keys/server.key").expect("Failed to read key file");

    let cert_chain = rustls_pemfile::certs(&mut cert.as_ref())
        .collect::<std::io::Result<Vec<CertificateDer<'static>>>>()
        .expect("Failed to load certs");
    let key_der = rustls_pemfile::private_key(&mut key.as_ref())
        .map(|k_opt| k_opt.expect("No PEM section describing private key found"))
        .expect("Failed to load private key");

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .expect("Failed to build rustls server config");

    server_config.alpn_protocols = match http_version {
        HttpVersion::HTTP1 => vec![b"http/1.1".to_vec()],
        HttpVersion::HTTP2 => vec![b"h2".to_vec()],
    };

    RustlsConfig::from_config(Arc::new(server_config))
}

async fn root() -> Html<&'static str> {
    Html(
        "<h1>Welcome to Random Bytes Server.</h1>
          <p>Use the /bytes/N endpoint to get N random bytes.</p>",
    )
}
