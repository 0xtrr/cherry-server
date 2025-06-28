use std::process::exit;

use crate::config::Config;
use crate::db::set_up_sqlite_db;
use crate::handlers::create_router;
use crate::utilities::file::create_directory_if_not_exists;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Pool, Sqlite};
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
    #[sqlx(skip)]
    url: String,
    sha256: String,
    size: i64,
    r#type: Option<String>,
    uploaded: i64,
}

impl Default for BlobDescriptor {
    fn default() -> Self {
        Self {
            url: String::new(),
            sha256: String::new(),
            size: 0,
            r#type: None,
            uploaded: 0,
        }
    }
}

impl BlobDescriptor {
    /// Construct the URL for this blob using the server configuration
    pub fn with_url(mut self, server_url: &str) -> Self {
        // Add an extension based on the MIME type
        let suffix = self.r#type
            .clone()
            .and_then(|mime_type| mime2ext::mime2ext(&mime_type))
            .map(|ext| ".".to_string() + ext)
            .unwrap_or("".to_string());
        
        self.url = format!("{}/{}{}", server_url, self.sha256, suffix);
        self
    }
}

#[derive(Parser)]
struct Args {
    /// Set the full path for the config file.
    #[clap(short, long = "config")]
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

    // Configure app state
    let app_state = AppState {
        config: config.clone(),
        pool: sqlite_pool,
    };

    // Configure the API routes
    let app = create_router(app_state).await;

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
