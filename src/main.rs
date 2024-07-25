use std::net::SocketAddr;

use axum::{extract::Path, http::StatusCode, response::Html, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use rand::Rng;
use std::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build application with necessary routes
    let app = Router::new()
        .route("/", get(root))
        .route("/bytes/:n", get(rand_bytes))
        .layer(TraceLayer::new_for_http());

    let addr = "127.0.0.1:3000".parse::<SocketAddr>().unwrap();
    tracing::info!("listenning on {}", addr);

    let listener = TcpListener::bind(addr).unwrap();

    let config = RustlsConfig::from_pem_file(
        "keys/server.crt",
        "keys/server.key"
    ).await.unwrap();

    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> Html<&'static str> {
    Html("<h1>Welcome to Random Bytes Server.</h1>
          <p>Use the /bytes/N endpoint to get N random bytes.</p>")
}

async fn rand_bytes(Path(n): Path<usize>) -> Result<Vec<u8>, StatusCode> {
    if n > 1000_000 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut rng = rand::thread_rng();
    Ok((0..n).map(|_| rng.gen::<u8>()).collect())
}
