use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, Sqlite, SqlitePool};
use std::fmt;
use std::fmt::Formatter;
use tracing::log::debug;

#[derive(Debug)]
pub enum Error {
    CreateDatabase(sqlx::Error),
    Connection(sqlx::Error),
    SetupSchema(sqlx::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::CreateDatabase(e) => write!(f, "failed to create database: {}", e),
            Error::Connection(e) => write!(f, "failed to connect to database: {}", e),
            Error::SetupSchema(e) => {
                write!(f, "failed to run the initial database schema: {}", e)
            }
        }
    }
}

pub async fn set_up_sqlite_db(database_url: String) -> Result<SqlitePool, Error> {
    if !Sqlite::database_exists(&database_url)
        .await
        .unwrap_or(false)
    {
        debug!("Existing database not found, creating new sqlite database");
        Sqlite::create_database(&database_url)
            .await
            .map_err(Error::CreateDatabase)?
    }

    // Connect to the sqlite database
    debug!("Connecting to sqlite database");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(Error::Connection)?;
    debug!("Connected to sqlite database");

    // Run the database schema setup script
    debug!("Running sqlite startup script");
    sqlx::query(include_str!("0001-schema.sql"))
        .execute(&pool)
        .await
        .map_err(Error::SetupSchema)?;
    debug!("Sqlite startup script finished successfully");

    // Run migration to remove url column if it exists
    debug!("Checking if url column migration is needed");
    let url_column_exists = sqlx::query("PRAGMA table_info(blob_descriptors)")
        .fetch_all(&pool)
        .await
        .map_err(Error::SetupSchema)?
        .iter()
        .any(|row| {
            let column_name: String = row.get("name");
            column_name == "url"
        });

    if url_column_exists {
        debug!("URL column found, running migration to remove it");
        sqlx::query(include_str!("0002-remove-url-column.sql"))
            .execute(&pool)
            .await
            .map_err(Error::SetupSchema)?;
        debug!("URL column migration completed successfully");
    } else {
        debug!("URL column not found, migration not needed");
    }

    Ok(pool)
}
