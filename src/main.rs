use std::process::exit;

use crate::config::Config;
use crate::db::set_up_sqlite_db;
use crate::handlers::{
    delete_blob_handler, get_blob_handler, has_blob_handler, list_blobs_handler,
    mirror_blob_handler, upload_blob_handler,
};
use crate::utilities::file::create_directory_if_not_exists;
use axum::http::Method;
use axum::routing::{get, put};
use axum::Router;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Pool, Sqlite};
use tower_http::cors::Any;
use tracing::log::{debug, error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod config;
mod db;
mod filter;
mod handlers;
mod utilities;

#[derive(Clone)]
struct AppState {
    config: Config,
    pool: Pool<Sqlite>,
}

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
struct BlobDescriptor {
    url: String,
    sha256: String,
    size: i64,
    r#type: Option<String>,
    uploaded: i64,
}

#[derive(Parser)]
struct Args {
    /// Set the full path for the config file.
    #[clap(short, long = "config-file-path")]
    config_file_path: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config_file_path = args
        .config_file_path
        .unwrap_or_else(|| "./config.toml".to_string());

    // Set environment for logging configuration
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Start logging to console
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::Layer::default().compact())
        .init();

    let config: Config =
        Config::load_from_file_path(config_file_path.as_str()).unwrap_or_else(|err| {
            error!("{}", err);
            exit(1)
        });
    debug!("Configuration file loaded from {}", config_file_path);

    // Ensure the blobs directory exists
    match create_directory_if_not_exists(&config.files_directory) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    }

    // Ensure the db directory exists
    match create_directory_if_not_exists(&config.database_directory) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    }

    // Ensure the sqlite database exists in above directory
    let sqlite_db_path = std::path::Path::new(&config.database_directory).join("cherry_server.db");
    let database_url = format!("sqlite://{}", sqlite_db_path.to_str().unwrap());

    let sqlite_pool = match set_up_sqlite_db(database_url).await {
        Ok(sqlite_pool) => sqlite_pool,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    // Configure CORS policy
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(vec![Method::GET, Method::PUT, Method::DELETE, Method::HEAD]);

    // Configure app state
    let app_state = AppState {
        config: config.clone(),
        pool: sqlite_pool,
    };

    // Configure the API routes
    let app = Router::new()
        .route(
            "/:hash",
            get(get_blob_handler)
                .head(has_blob_handler)
                .delete(delete_blob_handler),
        )
        .route("/upload", put(upload_blob_handler))
        .route("/list/:pubkey", get(list_blobs_handler))
        .route("/mirror", put(mirror_blob_handler))
        .layer(cors)
        .with_state(app_state);

    // Set up TCP listener
    debug!("Binding to {}", &config.host);
    let listener = tokio::net::TcpListener::bind(&config.host)
        .await
        .expect("Failed to bind to address");

    info!(
        "Application started successfully. Listening to {}",
        listener.local_addr().unwrap().to_string()
    );

    // Serve the REST API
    axum::serve(listener, app)
        .await
        .expect("Failed to serve application");
}
