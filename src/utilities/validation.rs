use std::fmt;
use std::fmt::Formatter;

use crate::utilities::get_sha256_hash;
use axum::body::Bytes;
use nostr_sdk::{Event, Kind, SingleLetterTag, TagKind, Timestamp};

#[derive(Debug)]
pub enum Error {
    // Kind number
    InvalidKind(Kind),
    AuthEventExpired,
    ExpirationTagMissing,
    MissingActionTag,
    // Expected action, Actual/provided action
    IncorrectAction(String, String),
    FilehashTagMissing,
    // Actual filehash
    FileHashMissing(String),
    InvalidCreatedAt(Timestamp),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKind(kind) => write!(f, "Invalid kind: {}", kind),
            Error::AuthEventExpired => write!(f, "Authorization event expired"),
            Error::ExpirationTagMissing => write!(
                f,
                "Required expiration tag missing from authorization event"
            ),
            Error::MissingActionTag => write!(f, "Missing action tag (t)"),
            Error::IncorrectAction(input_action, expected_action) => write!(
                f,
                "Incorrect action {}, expected {}",
                input_action, expected_action
            ),
            Error::FilehashTagMissing => write!(f, "Missing filehash tag (x)"),
            Error::FileHashMissing(actual) => {
                write!(f, "Missing filehash tag (x) for hash {}", actual)
            }
            Error::InvalidCreatedAt(created_at) => write!(f, "Invalid created_at: {}", created_at),
        }
    }
}

/// Validates the authorization event
pub fn validate_auth_event(auth_event: &Event, action: &str) -> Result<(), Error> {
    // Verify kind number
    if auth_event.kind != Kind::Custom(24242) {
        return Err(Error::InvalidKind(auth_event.kind));
    }

    // Verify that created_at is in the past
    if auth_event.created_at > Timestamp::now() {
        return Err(Error::InvalidCreatedAt(auth_event.created_at));
    }

    // Verify that the event hasn't expired
    match auth_event.get_tag_content(TagKind::Expiration) {
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
    if let Some(t_tag_value) = auth_event.get_tag_content(TagKind::SingleLetter(
        SingleLetterTag::from_char('t').unwrap(),
    )) {
        if t_tag_value == action {
            Ok(())
        } else {
            Err(Error::IncorrectAction(
                String::from(t_tag_value),
                action.to_string(),
            ))
        }
    } else {
        Err(Error::MissingActionTag)
    }
}

/// Validates hash against authorization event.
/// Returns the passed-in hash if it is present, an error otherwise.
pub fn validate_auth_event_x(auth_event: &Event, hash: &str) -> Result<String, Error> {
    let x_tags = auth_event.get_tags_content(TagKind::SingleLetter(
        SingleLetterTag::from_char('x').unwrap(),
    ));

    if x_tags.is_empty() {
        Err(Error::FilehashTagMissing)
    } else if x_tags.iter().any(|value| value == &hash) {
        Ok(hash.to_owned())
    } else {
        Err(Error::FileHashMissing(hash.to_owned()))
    }
}

/// Takes the auth header and the blob bytes.
///
/// If successful, returns the file hash. Else, returns an error.
pub fn validate_file_hash(auth_event: &Event, body: &Bytes) -> Result<String, Error> {
    let computed_hash = get_sha256_hash(body);

    validate_auth_event_x(auth_event, &computed_hash)
}
