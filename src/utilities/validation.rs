use std::fmt;
use std::fmt::Formatter;

use crate::utilities::get_sha256_hash;
use axum::body::Bytes;
use nostr_sdk::{Event, Kind, SingleLetterTag, Tag, TagKind, Timestamp};

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
    match auth_event.tags.clone().find(TagKind::Expiration) {
        Some(expiration) => {
            let expiration_value: u64 = match expiration.content() {
                None => 0,
                Some(exp) => exp.parse::<u64>().unwrap(),
            };
            if expiration_value < chrono::Utc::now().timestamp() as u64 {
                return Err(Error::AuthEventExpired);
            }
        }
        None => {
            // No Expiration tag found in the authorization event
            return Err(Error::ExpirationTagMissing);
        }
    }

    // Verify that a t-tag exists and has the correct value
    match auth_event.tags.find(TagKind::SingleLetter(
        SingleLetterTag::from_char('t').unwrap(),
    )) {
        Some(action_tag) => {
            if action_tag.content().unwrap() == action {
                Ok(())
            } else {
                Err(Error::IncorrectAction(
                    action.to_string(),
                    action_tag.content().unwrap().to_string(),
                ))
            }
        }
        None => Err(Error::MissingActionTag),
    }
}

/// Validates hash against authorization event.
/// Returns the passed-in hash if it is present, an error otherwise.
pub fn validate_auth_event_x(auth_event: &Event, hash: &str) -> Result<String, Error> {
    // Fetch all x tags from authorization event
    let x_tags: Vec<Tag> = auth_event
        .tags
        .clone()
        .into_iter()
        .filter(|tag| tag.kind() == TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap()))
        .filter(|tag| tag.content().is_some())
        .collect();

    if x_tags.is_empty() {
        // No x tags found
        Err(Error::FilehashTagMissing)
    } else if x_tags.iter().any(|tag| tag.content().unwrap() == hash) {
        // Found a match between the expected hash and one of the x tags in the authorization event
        Ok(hash.to_owned())
    } else {
        // No match between expected hash and authorization event tags
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

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys};

    #[test]
    fn test_validate_auth_event_invalid_kind() {
        let event = EventBuilder::new(Kind::TextNote, "test", vec![])
            .sign_with_keys(&Keys::generate())
            .unwrap();

        let result = validate_auth_event(&event, "upload");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidKind(_)));
    }

    #[test]
    fn test_validate_auth_event_invalid_created_at() {
        // Create event with invalid created_at
        let event = EventBuilder::new(Kind::Custom(24242), "test", vec![])
            .custom_created_at(Timestamp::from(chrono::Utc::now().timestamp() as u64 + 100))
            .sign_with_keys(&Keys::generate())
            .unwrap();

        let result = validate_auth_event(&event, "upload");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidCreatedAt(_)));
    }

    #[test]
    fn test_validate_auth_event_expired() {
        // Create event with expired expiration tag
        let event = EventBuilder::new(
            Kind::Custom(24242),
            "test",
            vec![Tag::custom(TagKind::Expiration, Some("1".to_string()))],
        )
        .sign_with_keys(&Keys::generate())
        .unwrap();

        let result = validate_auth_event(&event, "upload");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AuthEventExpired));
    }

    #[test]
    fn test_validate_auth_event_missing_expiration_tag() {
        // Create event with expired expiration tag
        let event = EventBuilder::new(Kind::Custom(24242), "test", vec![])
            .sign_with_keys(&Keys::generate())
            .unwrap();

        let result = validate_auth_event(&event, "upload");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ExpirationTagMissing));
    }

    #[test]
    fn test_validate_auth_event_incorrect_action() {
        // Create event with expired expiration tag
        let event = EventBuilder::new(
            Kind::Custom(24242),
            "test",
            vec![
                Tag::expiration(Timestamp::from(chrono::Utc::now().timestamp() as u64)),
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::from_char('t').unwrap()),
                    Some("download".to_string()),
                ),
            ],
        )
        .sign_with_keys(&Keys::generate())
        .unwrap();

        let result = validate_auth_event(&event, "upload");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::IncorrectAction(_, _)));
    }

    #[test]
    fn test_validate_auth_event_missing_action_tag() {
        // Create event with expired expiration tag
        let event = EventBuilder::new(
            Kind::Custom(24242),
            "test",
            vec![Tag::expiration(Timestamp::from(
                chrono::Utc::now().timestamp() as u64,
            ))],
        )
        .sign_with_keys(&Keys::generate())
        .unwrap();

        let result = validate_auth_event(&event, "upload");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::MissingActionTag));
    }

    #[test]
    fn test_validate_auth_event_valid() {
        // Create event with expired expiration tag
        let event = EventBuilder::new(
            Kind::Custom(24242),
            "test",
            vec![
                Tag::expiration(Timestamp::from(
                    chrono::Utc::now().timestamp() as u64 + 100000,
                )),
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::from_char('t').unwrap()),
                    Some("upload".to_string()),
                ),
            ],
        )
        .sign_with_keys(&Keys::generate())
        .unwrap();

        let result = validate_auth_event(&event, "upload");

        assert!(result.is_ok());
    }
}
