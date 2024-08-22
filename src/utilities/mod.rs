use axum::body::Bytes;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod file;
pub mod validation;

/// Gets the current unix timestamp in seconds
pub fn get_current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Takes the url path for a file containing the sha256 file hash and optionally a filetype.
///
/// Returns a tuple containing the file hash and the filetype if it exists.
pub fn split_filehash_and_filetype(filename: String) -> (String, Option<String>) {
    match filename.split_once('.') {
        Some((hash, ext)) => (hash.to_string(), Some(ext.to_string())),
        None => (filename, None),
    }
}

pub fn bytes_to_mb(bytes: f64) -> f64 {
    bytes / (1024.0 * 1024.0)
}

pub fn get_sha256_hash(bytes: &Bytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
