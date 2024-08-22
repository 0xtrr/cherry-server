use std::fmt;
use std::fmt::Formatter;

use axum::body::Bytes;

use crate::handlers::AuthEvent;
use crate::utilities::get_sha256_hash;

#[derive(Debug)]
pub enum Error {
    // Kind number
    InvalidKind(u64),
    AuthEventExpired,
    ExpirationTagMissing,
    MissingActionTag,
    // Expected action, Actual/provided action
    IncorrectAction(String, String),
    FilehashTagMissing,
    // Expected filehash (from auth event), actual filehash
    FileHashMismatch(String, String),
    InvalidCreatedAt(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKind(kind) => write!(f, "Invalid kind: {}", kind),
            Error::AuthEventExpired => write!(f, "Authorization event expired"),
            Error::ExpirationTagMissing => write!(f, "Required expiration tag missing from authorization event"),
            Error::MissingActionTag => write!(f, "Missing action tag (t)"),
            Error::IncorrectAction(input_action, expected_action) => write!(f, "Incorrect action {}, expected {}", input_action, expected_action),
            Error::FilehashTagMissing => write!(f, "Missing filehash tag (x)"),
            Error::FileHashMismatch(expected, actual) => write!(f, "File hash mismatch. Authorization event specified {}, but computed file hash was {}", expected, actual),
            Error::InvalidCreatedAt(created_at) => write!(f, "Invalid created_at: {}", created_at),
        }
    }
}

/// Validates the authorization event
pub fn validate_auth_event(auth_event: &AuthEvent, action: &str) -> Result<(), Error> {
    // Verify kind number
    if auth_event.kind != 24242 {
        return Err(Error::InvalidKind(auth_event.kind));
    }

    // Verify that created_at is in the past
    if auth_event.created_at > chrono::Utc::now().timestamp() as u64 {
        return Err(Error::InvalidCreatedAt(auth_event.created_at));
    }

    // Verify that the event hasn't expired
    match auth_event.tags.iter().find_map(|tag| {
        if tag[0] == "expiration" {
            tag.get(1)
        } else {
            None
        }
    }) {
        Some(expiration) => {
            let expiration: u64 = expiration.parse().unwrap_or(0);
            if expiration < chrono::Utc::now().timestamp() as u64 {
                return Err(Error::AuthEventExpired);
            }
        }
        None => {
            // No Expiration tag found in the authorization event
            return Err(Error::ExpirationTagMissing);
        }
    }

    // Verify that a t-tag exists and has the correct value
    if let Some(tag) = auth_event.tags.iter().find(|tag| tag[0] == "t") {
        if tag.len() > 1 && tag[1] == action {
            Ok(())
        } else {
            Err(Error::IncorrectAction(
                tag[1].to_string(),
                action.to_string(),
            ))
        }
    } else {
        Err(Error::MissingActionTag)
    }
}

/// Takes the auth header and the blob bytes.
///
/// If successful, returns the file hash. Else, returns an error.
pub fn validate_file_hash(auth_event: &AuthEvent, body: &Bytes) -> Result<String, Error> {
    let file_hash = extract_file_hash_from_auth_event(auth_event);
    if file_hash.is_empty() {
        return Err(Error::FilehashTagMissing);
    }

    let computed_hash = get_sha256_hash(body);

    if computed_hash.clone() != file_hash {
        return Err(Error::FileHashMismatch(file_hash, computed_hash));
    }
    Ok(computed_hash.clone())
}

/// Extracts the file hash from the auth event tags
pub fn extract_file_hash_from_auth_event(auth_event: &AuthEvent) -> String {
    if let Some(tag) = auth_event.tags.iter().find(|tag| tag[0] == "x") {
        tag.get(1).cloned().unwrap_or_default()
    } else {
        String::new()
    }
}
