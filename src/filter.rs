use std::fmt;
use std::fmt::Formatter;

use crate::config::{Config, UploadFilterListMode};

#[derive(Debug)]
pub enum Error {
    PublicKeyNotAllowed(String),
    MimeTypeNotAllowed(String),
    MimeTypeMissing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::PublicKeyNotAllowed(public_key) => write!(
                f,
                "Public key {} not allowed to upload to this server",
                public_key
            ),
            Error::MimeTypeNotAllowed(mime_type) => write!(
                f,
                "MIME type {} not allowed to be uploaded to this server",
                mime_type
            ),
            Error::MimeTypeMissing => write!(
                f,
                "Unable to determine MIME type, Content-Type header not found in request headers"
            ),
        }
    }
}

impl std::error::Error for Error {}

pub fn is_public_key_allowed_to_upload(config: &Config, pubkey: &str) -> Result<(), Error> {
    // Only check if filter is enabled
    if config.upload.public_key_filter.enabled {
        match config.upload.public_key_filter.mode {
            UploadFilterListMode::Whitelist => {
                if config
                    .upload
                    .public_key_filter
                    .public_keys
                    .contains(&pubkey.to_string())
                {
                    Ok(())
                } else {
                    Err(Error::PublicKeyNotAllowed(pubkey.to_string()))
                }
            }
            UploadFilterListMode::Blacklist => {
                if config
                    .upload
                    .public_key_filter
                    .public_keys
                    .contains(&pubkey.to_string())
                {
                    Err(Error::PublicKeyNotAllowed(pubkey.to_string()))
                } else {
                    Ok(())
                }
            }
        }
    } else {
        Ok(())
    }
}

pub fn is_mime_type_allowed(config: &Config, mime_type: &Option<String>) -> Result<(), Error> {
    // Only check if filter is enabled
    if config.upload.mimetype_filter.enabled {
        match mime_type {
            None => {
                // Return error if Content-Type header is empty or missing
                Err(Error::MimeTypeMissing)
            }
            Some(mime_type) => match config.upload.mimetype_filter.mode {
                UploadFilterListMode::Whitelist => {
                    if config
                        .upload
                        .mimetype_filter
                        .mime_types
                        .contains(&mime_type.to_string())
                    {
                        Ok(())
                    } else {
                        Err(Error::MimeTypeNotAllowed(mime_type.to_string()))
                    }
                }
                UploadFilterListMode::Blacklist => {
                    if config
                        .upload
                        .mimetype_filter
                        .mime_types
                        .contains(&mime_type.to_string())
                    {
                        Err(Error::MimeTypeNotAllowed(mime_type.to_string()))
                    } else {
                        Ok(())
                    }
                }
            },
        }
    } else {
        Ok(())
    }
}
