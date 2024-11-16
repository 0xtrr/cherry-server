use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::filter::{is_mime_type_allowed, is_public_key_allowed_to_upload};
use crate::utilities::file::{
    delete_blob_from_filesystem, get_blob_from_filesystem, write_blob_to_file,
};
use crate::utilities::validation::{
    validate_auth_event, validate_auth_event_x, validate_file_hash,
};
use crate::utilities::{bytes_to_mb, get_current_unix_timestamp, split_filehash_and_filetype};
use crate::{utilities, AppState, BlobDescriptor};
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use base64::engine::general_purpose;
use base64::Engine;
use nostr_sdk::{Event, PublicKey, SingleLetterTag, TagKind};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::query_as;
use tower_http::cors::Any;
use tracing::log::error;

#[derive(Debug)]
pub struct AuthHeader(pub Option<Event>);

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthEvent {
    pub id: String,
    pub pubkey: String,
    pub kind: u64,
    pub content: String,
    pub created_at: u64,
    pub tags: Vec<Vec<String>>,
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

/// Used in authorization header inspection
fn unauthorized_error_response(message: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::UNAUTHORIZED, Json(ErrorResponse { message }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MirrorRequest {
    pub url: String,
}

/// Custom-built Axum header extractor that fetches and parses the Nostr authorization token from the
/// 'Authorization' HTTP header.
#[async_trait::async_trait]
impl<S> FromRequestParts<S> for AuthHeader
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let auth_header = if let Some(auth_header) = parts.headers.get("Authorization") {
            auth_header
        } else {
            return Ok(AuthHeader(None));
        };

        let auth_str = auth_header
            .to_str()
            .map_err(|_| unauthorized_error_response("Invalid Authorization header".to_string()))?;

        if !auth_str.starts_with("Nostr") {
            return Err(unauthorized_error_response(
                "Invalid Authorization header".to_string(),
            ));
        }

        let encoded_event = auth_str.strip_prefix("Nostr ").unwrap();
        let decoded_event = general_purpose::STANDARD
            .decode(encoded_event)
            .map_err(|err| {
                unauthorized_error_response(format!("Invalid base64 encoding: {}", err))
            })?;

        match serde_json::from_slice::<Event>(&decoded_event) {
            Ok(event) => match event.verify_signature() {
                true => Ok(AuthHeader(Some(event))),
                false => Err(unauthorized_error_response(
                    "Invalid signature in authorization event".to_string(),
                )),
            },
            Err(err) => Err(unauthorized_error_response(format!(
                "Invalid authorization event: {}",
                err
            ))),
        }
    }
}

pub async fn create_router(app_state: AppState) -> Router {
    // Configure CORS policy
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(vec![Method::GET, Method::PUT, Method::DELETE, Method::HEAD]);

    // Configure router
    Router::new()
        .route("/", get(|| async { Html(include_str!("html/index.html")) }))
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
        .with_state(app_state)
}

pub async fn get_blob_handler(
    Path(file_hash): Path<String>,
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
) -> impl IntoResponse {
    // Get the file hash and file type
    let (file_hash, _filetype) = split_filehash_and_filetype(file_hash);

    // Handle auth event if required
    if app_state.config.get.require_auth {
        match auth_event {
            Some(ref auth_event) => {
                // Validate kind, created_at, expiration tag and t-tag (action)
                if let Err(error_msg) = validate_auth_event(auth_event, "get") {
                    let json = Json(ErrorResponse {
                        message: error_msg.to_string(),
                    });
                    return (StatusCode::UNAUTHORIZED, json).into_response();
                }

                // Verify x/server tag
                let has_server_tag = &auth_event
                    .tags
                    .iter()
                    .any(|tag| tag.kind() == TagKind::custom("server") && tag.content().unwrap() == app_state.config.server_url);

                let has_x_tag = &auth_event
                    .tags
                    .iter()
                    .any(|tag| tag.kind() == TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap()) && tag.content().unwrap() == file_hash);

                if !has_server_tag && !has_x_tag {
                    let json = Json(ErrorResponse {
                        message: "No matching x tag or server tag in authorization event".to_string(),
                    });
                    return (StatusCode::UNAUTHORIZED, json).into_response();
                }
            }
            None => {
                let json = Json(ErrorResponse {
                    message: "Missing authorization event".to_string(),
                });
                return (StatusCode::UNAUTHORIZED, json).into_response();
            }
        }
    }

    let blob_descriptor = if app_state.config.get.require_auth {
        let result = query_as::<_, BlobDescriptor>(
            "SELECT * FROM blob_descriptors WHERE sha256 = ? AND pubkey = ?",
        )
        .bind(&file_hash)
        .bind(auth_event.unwrap().pubkey.to_hex())
        .fetch_optional(&app_state.pool)
        .await
        .unwrap();

        if result.is_none() {
            return (StatusCode::NOT_FOUND).into_response();
        }
        result
    } else {
        let result =
            query_as::<_, BlobDescriptor>("SELECT * FROM blob_descriptors WHERE sha256 = ?")
                .bind(&file_hash)
                .fetch_optional(&app_state.pool)
                .await
                .unwrap();
        if result.is_none() {
            return (StatusCode::NOT_FOUND).into_response();
        }
        result
    };

    // Get blob from filesystem
    let file_contents =
        match get_blob_from_filesystem(&app_state.config.files_directory, &file_hash) {
            Ok(file_contents) => file_contents,
            Err(e) => {
                return match e {
                    utilities::file::Error::ReadFile => {
                        let error_response = ErrorResponse {
                            message: "Failed to read blob".to_string(),
                        };
                        let json = Json(error_response);
                        (StatusCode::INTERNAL_SERVER_ERROR, json).into_response()
                    }
                    utilities::file::Error::FileNotFound => {
                        let error_response = ErrorResponse {
                            message: "Blob not found".to_string(),
                        };
                        let json = Json(error_response);
                        (StatusCode::NOT_FOUND, json).into_response()
                    }
                    utilities::file::Error::OpenFile => {
                        let error_response = ErrorResponse {
                            message: "Failed to read blob".to_string(),
                        };
                        let json = Json(error_response);
                        (StatusCode::INTERNAL_SERVER_ERROR, json).into_response()
                    }
                    _ => {
                        // TODO: This should never happen, maybe this handling needs some refactoring
                        let error_response = ErrorResponse {
                            message: "Something went wrong".to_string(),
                        };
                        let json = Json(error_response);
                        (StatusCode::INTERNAL_SERVER_ERROR, json).into_response()
                    }
                };
            }
        };

    let content_type = blob_descriptor
        .as_ref()
        .and_then(|desc| desc.r#type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Cache-Control", "max-age=31536000, immutable")
        .body(file_contents.into())
        .unwrap()
}

pub async fn has_blob_handler(
    Path(file_hash): Path<String>,
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let (file_hash, _filetype) = split_filehash_and_filetype(file_hash);
    let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
    if PathBuf::from(&file_path).exists() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
}

pub async fn list_blobs_handler(
    Path(pubkey): Path<String>,
    Query(params): Query<ListQuery>,
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
) -> impl IntoResponse {
    if app_state.config.list.require_auth {
        let path_public_key = match PublicKey::from_hex(&pubkey) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                error!("{}", err);
                let json = Json(ErrorResponse {
                    message: "Unable to parse public key in path".to_string(),
                });
                return (StatusCode::BAD_REQUEST, json).into_response();
            }
        };
        match auth_event {
            Some(ref auth_event) => {
                if auth_event.pubkey != path_public_key {
                    let json = Json(ErrorResponse {
                        message: "Public key mismatch in authorization event and url path"
                            .to_string(),
                    });
                    return (StatusCode::UNAUTHORIZED, json).into_response();
                }
                // Validate kind, expiration tag and t-tag (action)
                if let Err(error_msg) = validate_auth_event(auth_event, "list") {
                    let json = Json(ErrorResponse {
                        message: error_msg.to_string(),
                    });
                    return (StatusCode::UNAUTHORIZED, json).into_response();
                }
            }
            None => {
                let json = Json(ErrorResponse {
                    message: "Missing authorization event".to_string(),
                });
                return (StatusCode::UNAUTHORIZED, json).into_response();
            }
        }
    }
    let mut query = String::from("SELECT * FROM blob_descriptors WHERE pubkey = ?");
    if params.since.is_some() {
        query.push_str(" AND uploaded >= ?");
    }
    if params.until.is_some() {
        query.push_str(" AND uploaded <= ?");
    }

    let mut stmt = sqlx::query_as::<_, BlobDescriptor>(&query).bind(pubkey);

    if let Some(since) = params.since {
        stmt = stmt.bind(since);
    }

    if let Some(until) = params.until {
        stmt = stmt.bind(until);
    }

    let blob_descriptors = stmt.fetch_all(&app_state.pool).await.unwrap();

    Json(blob_descriptors).into_response()
}

pub async fn upload_blob_handler(
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Validate that uploads are enabled
    if !app_state.config.upload.enabled {
        let json = Json(ErrorResponse {
            message: "Uploads are disabled".to_string(),
        });
        return (StatusCode::NOT_FOUND, json).into_response();
    }

    // Get the auth event from HTTP headers
    let auth_event = match auth_event {
        Some(auth_event) => auth_event,
        None => {
            let json = Json(ErrorResponse {
                message: "Authorization event required to upload a blob".to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    };

    // Validate the authorization event
    match validate_auth_event(&auth_event, "upload") {
        Ok(_) => {}
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    }

    // Validate the file hash against the hash defined in the authorization event
    let file_hash = match validate_file_hash(&auth_event, &body) {
        Ok(file_hash) => file_hash,
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::BAD_REQUEST, json).into_response();
        }
    };

    // Check that the size of the blob does not exceed the limit set in the upload config
    let blob_size_in_mb = bytes_to_mb(body.len() as f64);
    if blob_size_in_mb > app_state.config.upload.max_size {
        let json = Json(ErrorResponse {
            message: format!(
                "Blob size is {} MB, max upload size is {}",
                blob_size_in_mb, app_state.config.upload.max_size
            ),
        });
        return (StatusCode::BAD_REQUEST, json).into_response();
    }

    // Check if public key is allowed to upload to the server
    if let Err(e) = is_public_key_allowed_to_upload(&app_state.config, &auth_event.pubkey) {
        let json = Json(ErrorResponse {
            message: e.to_string(),
        });
        return (StatusCode::UNAUTHORIZED, json).into_response();
    }

    // Get the value of the Content-Type header
    let content_type = headers
        .get("Content-Type")
        .map(|v| v.to_str().unwrap_or_default().to_string());

    // Validate the MIME type
    if let Err(e) = is_mime_type_allowed(&app_state.config, &content_type) {
        let json = Json(ErrorResponse {
            message: e.to_string(),
        });
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, json).into_response();
    }

    // Write blob to file system
    let file_storage_dir = std::path::Path::new(&app_state.config.files_directory);

    match write_blob_to_file(file_storage_dir, &file_hash, body.clone()) {
        Ok(_) => {}
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::INTERNAL_SERVER_ERROR, json).into_response();
        }
    }

    // Define Blob Descriptor
    let blob_descriptor = BlobDescriptor {
        url: format!("{}/{}", app_state.config.server_url, file_hash),
        sha256: file_hash.clone(),
        size: body.len() as i64,
        r#type: content_type,
        uploaded: get_current_unix_timestamp() as i64,
    };

    // Insert the blob descriptor into the sqlite database
    let result = sqlx::query(
        "INSERT INTO blob_descriptors (url, sha256, size, type, uploaded, pubkey) VALUES (?, ?, ?, ?, ?, ?)"
    )
        .bind(&blob_descriptor.url)
        .bind(&blob_descriptor.sha256)
        .bind(blob_descriptor.size)
        .bind(&blob_descriptor.r#type)
        .bind(blob_descriptor.uploaded)
        .bind(auth_event.pubkey.to_hex())
        .execute(&app_state.pool)
        .await;

    match result {
        Ok(_) => {
            // Update the reference count in the database
            let reference_update_result = sqlx::query(
                "INSERT INTO file_references (sha256, reference_count) VALUES (?, 1)
         ON CONFLICT(sha256) DO UPDATE SET reference_count = reference_count + 1",
            )
            .bind(&file_hash)
            .execute(&app_state.pool)
            .await;

            if let Err(e) = reference_update_result {
                let error_message = ErrorResponse {
                    // TODO: Consider a better error message to return to the user
                    message: format!("Failed to update file reference count: {}", e),
                };
                let json = Json(error_message);
                return (StatusCode::INTERNAL_SERVER_ERROR, json).into_response();
            }
            Json(blob_descriptor).into_response()
        }
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            let error_message = ErrorResponse {
                message: "Blob already uploaded by this public key".to_string(),
            };
            let json = Json(error_message);
            (StatusCode::CONFLICT, json).into_response()
        }
        Err(_) => {
            let error_message = ErrorResponse {
                message: "Failed to insert blob descriptor".to_string(),
            };
            let json = Json(error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, json).into_response()
        }
    }
}

pub async fn delete_blob_handler(
    Path(file_hash): Path<String>,
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
) -> impl IntoResponse {
    // Get the auth event from HTTP headers
    let auth_event = match auth_event {
        Some(auth_event) => auth_event,
        None => {
            let json = Json(ErrorResponse {
                message: "Authorization event required to delete a blob".to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    };

    let (path_file_hash, _filetype) = split_filehash_and_filetype(file_hash);

    // Validate the authorization event
    match validate_auth_event(&auth_event, "delete") {
        Ok(_) => {}
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    }

    if let Err(err) = validate_auth_event_x(&auth_event, &path_file_hash) {
        let json = Json(ErrorResponse {
            message: err.to_string(),
        });
        return (StatusCode::UNAUTHORIZED, json).into_response();
    }

    // Ensure the file exists in the database
    match sqlx::query("SELECT 1 FROM blob_descriptors WHERE sha256 = ? AND pubkey = ?")
        .bind(&path_file_hash)
        .bind(auth_event.pubkey.to_hex())
        .fetch_optional(&app_state.pool)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let error_response = ErrorResponse {
                message: "Blob not found".to_string(),
            };
            return (StatusCode::NOT_FOUND, Json(error_response)).into_response();
        }
        Err(e) => {
            error!("{}", e);
            let error_response = ErrorResponse {
                message: "Database error".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Delete file blob descriptor from the sqlite database
    match sqlx::query("DELETE FROM blob_descriptors WHERE sha256 = ? AND pubkey = ?")
        .bind(&path_file_hash)
        .bind(auth_event.pubkey.to_hex())
        .execute(&app_state.pool)
        .await
    {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            let error_response = ErrorResponse {
                message: "Failed to delete blob descriptor".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Update reference count and delete file if count drops to zero
    match sqlx::query(
        "UPDATE file_references SET reference_count = reference_count - 1 WHERE sha256 = ?",
    )
    .bind(&path_file_hash)
    .execute(&app_state.pool)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            let error_response = ErrorResponse {
                message: "Failed to update reference count".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Check if reference count is zero
    let reference_count: i64 =
        sqlx::query_scalar("SELECT reference_count FROM file_references WHERE sha256 = ?")
            .bind(&path_file_hash)
            .fetch_one(&app_state.pool)
            .await
            .unwrap_or(0);

    if reference_count <= 0 {
        // Delete file from filesystem
        match delete_blob_from_filesystem(&app_state.config.files_directory, &path_file_hash) {
            Ok(_) => {}
            Err(error_msg) => {
                error!("{}", error_msg);
                let error_response = ErrorResponse {
                    message: error_msg.to_string(),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
            }
        }
    }

    (StatusCode::NO_CONTENT).into_response()
}

pub async fn mirror_blob_handler(
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
    Json(mirror_request): Json<MirrorRequest>,
) -> impl IntoResponse {
    // Return error if not enabled
    if !app_state.config.mirror.enable {
        let json = Json(ErrorResponse {
            message: "Mirror endpoint is not enabled".to_string(),
        });
        return (StatusCode::NOT_FOUND, json).into_response();
    }

    // Get the auth event from HTTP headers
    let auth_event = match auth_event {
        Some(auth_event) => auth_event,
        None => {
            let json = Json(ErrorResponse {
                message: "Authorization event required to upload a blob".to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    };

    // Validate the authorization event
    match validate_auth_event(&auth_event, "upload") {
        Ok(_) => {}
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::UNAUTHORIZED, json).into_response();
        }
    }

    let client = Client::new();
    let response = match client.get(&mirror_request.url).send().await {
        Ok(response) => response,
        Err(_) => {
            let error_response = ErrorResponse {
                message: "Failed to download blob".to_string(),
            };
            let json = Json(error_response);
            return (StatusCode::BAD_REQUEST, json).into_response();
        }
    };

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    let blob_data = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error_response = ErrorResponse {
                message: "Failed to read blob data".to_string(),
            };
            let json = Json(error_response);
            return (StatusCode::BAD_REQUEST, json).into_response();
        }
    };

    // Validate the file hash against the hash defined in the authorization event
    let file_hash = match validate_file_hash(&auth_event, &blob_data) {
        Ok(file_hash) => file_hash,
        Err(error_msg) => {
            let json = Json(ErrorResponse {
                message: error_msg.to_string(),
            });
            return (StatusCode::BAD_REQUEST, json).into_response();
        }
    };

    let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
    let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(_) => {
            let error_message = ErrorResponse {
                message: "Failed to write blob".to_string(),
            };
            let json = Json(error_message);
            return (StatusCode::INTERNAL_SERVER_ERROR, json).into_response();
        }
    };

    if file.write_all(&blob_data).is_err() {
        let error_message = ErrorResponse {
            message: "Failed to write blob".to_string(),
        };
        let json = Json(error_message);
        return (StatusCode::INTERNAL_SERVER_ERROR, json).into_response();
    }

    let blob_descriptor = BlobDescriptor {
        url: format!("{}/{}", app_state.config.server_url, file_hash),
        sha256: file_hash,
        size: blob_data.len() as i64,
        r#type: content_type,
        uploaded: get_current_unix_timestamp() as i64,
    };

    let result = sqlx::query(
        "INSERT INTO blob_descriptors (url, sha256, size, type, uploaded, pubkey) VALUES (?, ?, ?, ?, ?, ?)"
    )
        .bind(&blob_descriptor.url)
        .bind(&blob_descriptor.sha256)
        .bind(blob_descriptor.size)
        .bind(&blob_descriptor.r#type)
        .bind(blob_descriptor.uploaded)
        .bind(auth_event.pubkey.to_hex())
        .execute(&app_state.pool)
        .await;

    match result {
        Ok(_) => Json(blob_descriptor).into_response(),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            let error_message = ErrorResponse {
                message: "Blob already mirrored by this public key".to_string(),
            };
            let json = Json(error_message);
            (StatusCode::CONFLICT, json).into_response()
        }
        Err(_) => {
            let error_message = ErrorResponse {
                message: "Failed to insert blob descriptor".to_string(),
            };
            let json = Json(error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, json).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        Config, GetBlobConfig, ListConfig, MirrorConfig, UploadBlobConfig, UploadFilterListMode,
        UploadMimeTypeConfig, UploadPublicKeyConfig,
    };
    use crate::db::set_up_sqlite_db;
    use crate::handlers::create_router;
    use crate::utilities::file::write_blob_to_file;
    use crate::utilities::get_sha256_hash;
    use crate::{AppState, BlobDescriptor};
    use axum::body::{Body, Bytes};
    use axum::http;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use http_body_util::BodyExt;
    use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, SingleLetterTag, Tag, TagKind, Timestamp};
    use std::env::temp_dir;
    use std::ops::Add;
    use std::path::Path;
    use std::time::SystemTime;
    use tower::ServiceExt;

    #[tokio::test]
    async fn get_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let app_state: AppState = set_up_app_state().await;
        let app = create_router(app_state.clone()).await;

        // Create a test blob descriptor
        let file_hash =
            "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553".to_string();
        let blob_descriptor = BlobDescriptor {
            url: format!("{}/{}", app_state.config.server_url, file_hash),
            sha256: file_hash.clone(),
            size: 1024,
            r#type: Some("text/plain".to_string()),
            uploaded: 1643723400,
        };

        // Insert the blob descriptor into the database
        sqlx::query(
            "INSERT INTO blob_descriptors (url, sha256, size, type, uploaded, pubkey) VALUES (?, ?, ?, ?, ?, ?)",
        )
            .bind(&blob_descriptor.url)
            .bind(&blob_descriptor.sha256)
            .bind(blob_descriptor.size)
            .bind(&blob_descriptor.r#type)
            .bind(blob_descriptor.uploaded)
            .bind(keypair.public_key().to_hex())
            .execute(&app_state.pool)
            .await
            .unwrap();

        // Create a test file to store in the file directory.
        let file_contents = b"Hello, World!";
        write_blob_to_file(
            &Path::new(&app_state.config.files_directory),
            &file_hash,
            Bytes::from(file_contents.to_vec()),
        )
        .unwrap();

        // Send a GET request to retrieve the blob.
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(&format!("/{}", file_hash))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that the response status code is OK (200).
        assert_eq!(response.status(), StatusCode::OK);

        // Verify that the response body matches the expected file contents.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], file_contents);
    }

    #[tokio::test]
    async fn has_blob_handler_test() {
        // Set up app config and axum router
        let app_state: AppState = set_up_app_state().await;
        let app = create_router(app_state.clone()).await;

        // File hash used as filename
        let file_hash =
            "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553".to_string();

        // Create a test file
        let file_contents = b"Hello, World!";
        write_blob_to_file(
            &Path::new(&app_state.config.files_directory),
            &file_hash,
            Bytes::from(file_contents.to_vec()),
        )
        .unwrap();

        // Execute HTTP request to check if file exists
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::HEAD)
                    .uri(&format!("/{}", file_hash))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify expected HTTP response code
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_blobs_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let app_state: AppState = set_up_app_state().await;
        let app = create_router(app_state.clone()).await;

        // Create a test blob descriptor
        let file_hash =
            "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553".to_string();
        let blob_descriptor = BlobDescriptor {
            url: format!("{}/{}", app_state.config.server_url, file_hash),
            sha256: file_hash.clone(),
            size: 1024,
            r#type: Some("application/octet-stream".to_string()),
            uploaded: 1643723400,
        };

        // Insert the blob descriptor into the database
        sqlx::query(
            "INSERT INTO blob_descriptors (url, sha256, size, type, uploaded, pubkey) VALUES (?, ?, ?, ?, ?, ?)",
        )
            .bind(&blob_descriptor.url)
            .bind(&blob_descriptor.sha256)
            .bind(blob_descriptor.size)
            .bind(&blob_descriptor.r#type)
            .bind(blob_descriptor.uploaded)
            .bind(keypair.public_key().to_hex())
            .execute(&app_state.pool)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(&format!("/list/{}", keypair.public_key().to_hex()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let blobs: Vec<BlobDescriptor> = serde_json::from_slice(&body).unwrap();

        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].url, blob_descriptor.url);
        assert_eq!(blobs[0].sha256, blob_descriptor.sha256);
        assert_eq!(blobs[0].size, blob_descriptor.size);
        assert_eq!(blobs[0].r#type, blob_descriptor.r#type);
        assert_eq!(blobs[0].uploaded, blob_descriptor.uploaded);
    }

    #[tokio::test]
    async fn upload_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let app_state: AppState = set_up_app_state().await;
        let app = create_router(app_state.clone()).await;

        // Create a test blob
        let file_contents = b"Hello, World!";
        let file_hash = get_sha256_hash(&Bytes::from(file_contents.to_vec()));

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap()),
                vec![file_hash.to_owned()],
            ),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .body(Body::from(file_contents.to_vec()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let blob_descriptor: BlobDescriptor = serde_json::from_slice(&body).unwrap();

        assert_eq!(blob_descriptor.sha256, file_hash);
        assert_eq!(blob_descriptor.size, file_contents.len() as i64);
        assert_eq!(blob_descriptor.r#type, Some("text/plain".to_string()));

        let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
        assert!(std::path::Path::new(&file_path).exists());
    }

    #[tokio::test]
    async fn delete_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let app_state: AppState = set_up_app_state().await;
        let app = create_router(app_state.clone()).await;

        // Create a test blob descriptor
        let file_hash =
            "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553".to_string();
        let blob_descriptor = BlobDescriptor {
            url: format!("{}/{}", app_state.config.server_url, file_hash),
            sha256: file_hash.clone(),
            size: 1024,
            r#type: Some("application/octet-stream".to_string()),
            uploaded: 1643723400,
        };

        // Insert the blob descriptor into the database
        sqlx::query(
            "INSERT INTO blob_descriptors (url, sha256, size, type, uploaded, pubkey) VALUES (?, ?, ?, ?, ?, ?)",
        )
            .bind(&blob_descriptor.url)
            .bind(&blob_descriptor.sha256)
            .bind(blob_descriptor.size)
            .bind(&blob_descriptor.r#type)
            .bind(blob_descriptor.uploaded)
            .bind(keypair.public_key().to_hex())
            .execute(&app_state.pool)
            .await
            .unwrap();

        // Store the file
        let file_contents = b"Hello, World!";
        write_blob_to_file(
            &Path::new(&app_state.config.files_directory),
            &file_hash,
            Bytes::from(file_contents.to_vec()),
        )
        .unwrap();

        // Verify that the file actually exists
        let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
        assert!(Path::new(&file_path).exists());

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("delete"),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap()),
                vec![file_hash.to_owned()],
            ),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "delete".to_string(), tags);

        // Send DELETE request to our handler
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri(&format!("/{}", file_hash))
            .header("Authorization", format!("Nostr {}", auth_header))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();

        // Verify expected HTTP response status
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify that the file does not exist anymore
        assert!(!Path::new(&file_path).exists());

        // Verify that we don't have any blob descriptors anymore
        let result: Option<BlobDescriptor> =
            sqlx::query_as("SELECT * FROM blob_descriptors WHERE sha256 = ? AND pubkey = ?")
                .bind(&file_hash)
                .bind(keypair.public_key().to_hex())
                .fetch_optional(&app_state.pool)
                .await
                .unwrap();

        assert!(result.is_none());
    }


    /// Sets up a test `AppState` instance with a temporary database and file directory.
    ///
    /// This method creates a temporary directory, sets up a SQLite database within it,
    /// and creates a test `Config` instance with default values. It then returns an `AppState`
    /// instance with the test configuration and database pool.
    ///
    /// The test configuration has the following properties:
    ///
    /// *   `database_directory`: The temporary directory where the database is stored.
    /// *   `files_directory`: The temporary directory where files are stored.
    /// *   `server_url`: "https://example.com".
    /// *   `host`: "127.0.0.1:8080".
    /// *   `get`: `GetBlobConfig` with `require_auth` set to `false`.
    /// *   `upload`: `UploadBlobConfig` with `enabled` set to `true`, `max_size` set to 1024.0,
    ///     and default public key and MIME type filter configurations.
    /// *   `list`: `ListConfig` with `require_auth` set to `false`.
    /// *   `mirror`: `MirrorConfig` with `enable` set to `false`.
    ///
    /// This method is intended for use in tests to create a test `AppState` instance with a
    /// temporary database and file directory.
    async fn set_up_app_state() -> AppState {
        let temp_dir = temp_dir();
        let db_dir = temp_dir.as_path();
        let db_url = format!("sqlite://{}", db_dir.join("test.db").display());
        let pool = set_up_sqlite_db(db_url).await.unwrap();

        let config = Config {
            database_directory: db_dir.to_string_lossy().into(),
            files_directory: temp_dir.as_path().join("files").to_string_lossy().into(),
            server_url: "https://example.com".to_string(),
            host: "127.0.0.1:8080".to_string(),
            get: GetBlobConfig {
                require_auth: false,
            },
            upload: UploadBlobConfig {
                enabled: true,
                max_size: 1024.0,
                public_key_filter: UploadPublicKeyConfig {
                    enabled: false,
                    mode: UploadFilterListMode::Whitelist,
                    public_keys: vec![],
                },
                mimetype_filter: UploadMimeTypeConfig {
                    enabled: false,
                    mode: UploadFilterListMode::Whitelist,
                    mime_types: vec![],
                },
            },
            list: ListConfig {
                require_auth: false,
            },
            mirror: MirrorConfig { enable: false },
        };

        AppState { config, pool }
    }

    fn generate_blossom_auth_header(keys: Keys, action: String, tags: Vec<Tag>) -> String {
        let json_event = EventBuilder::new(Kind::Custom(24242), action, tags)
            .sign_with_keys(&keys)
            .unwrap()
            .as_json();
        base64::engine::general_purpose::STANDARD.encode(json_event)
    }
}
