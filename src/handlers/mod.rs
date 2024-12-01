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
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use base64::engine::general_purpose;
use base64::Engine;
use mime2ext::mime2ext;
use nostr_sdk::{Event, PublicKey, SingleLetterTag, TagKind};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::{query_as, Error};
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

fn build_unauthorized_error_response(message: &str) -> Response {
    build_error_response(StatusCode::UNAUTHORIZED, message)
}

fn build_not_found_error_response(message: &str) -> Response {
    build_error_response(StatusCode::NOT_FOUND, message)
}

fn build_bad_request_error_response(message: &str) -> Response {
    build_error_response(StatusCode::BAD_REQUEST, message)
}

fn build_conflict_error_response(message: &str) -> Response {
    build_error_response(StatusCode::CONFLICT, message)
}
fn build_internal_server_error_response(message: &str) -> Response {
    build_error_response(StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn build_error_response(status_code: StatusCode, message: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("X-Reason", HeaderValue::from_str(message).unwrap());
    (status_code, headers).into_response()
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
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let auth_header = if let Some(auth_header) = parts.headers.get("Authorization") {
            auth_header
        } else {
            return Ok(AuthHeader(None));
        };

        let auth_str = auth_header
            .to_str()
            .map_err(|_| build_unauthorized_error_response("Invalid Authorization header"))?;

        if !auth_str.starts_with("Nostr") {
            return Err(build_unauthorized_error_response(
                "Invalid Authorization header",
            ));
        }

        let encoded_event = auth_str.strip_prefix("Nostr ").unwrap();
        let decoded_event = general_purpose::STANDARD
            .decode(encoded_event)
            .map_err(|err| {
                build_unauthorized_error_response(
                    format!("Invalid base64 encoding: {}", err).as_str(),
                )
            })?;

        match serde_json::from_slice::<Event>(&decoded_event) {
            Ok(event) => match event.verify_signature() {
                true => Ok(AuthHeader(Some(event))),
                false => Err(build_unauthorized_error_response(
                    "Invalid signature in authorization event",
                )),
            },
            Err(err) => Err(build_unauthorized_error_response(
                format!("Invalid authorization event: {}", err).as_str(),
            )),
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
        .route(
            "/upload",
            put(upload_blob_handler).head(upload_head_handler),
        )
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
                    return build_unauthorized_error_response(error_msg.to_string().as_str());
                }

                // Verify x/server tag
                let has_server_tag = &auth_event.tags.iter().any(|tag| {
                    tag.kind() == TagKind::custom("server")
                        && tag.content().unwrap() == app_state.config.server_url
                });

                let has_x_tag = &auth_event.tags.iter().any(|tag| {
                    tag.kind() == TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap())
                        && tag.content().unwrap() == file_hash
                });

                if !has_server_tag && !has_x_tag {
                    return build_unauthorized_error_response(
                        "No matching x tag or server tag in authorization event",
                    );
                }
            }
            None => return build_unauthorized_error_response("Missing authorization event"),
        }
    }

    // Define which query to run. By default, we always search for a blob descriptor using the
    // file hash provided in the url path. If auth is required, we also use the auth event pubkey
    // when searching for a blob descriptor.
    let blob_descriptor_query = match app_state.config.get.require_auth {
        true => query_as::<_, BlobDescriptor>(
            "SELECT * FROM blob_descriptors WHERE sha256 = ? AND pubkey = ?",
        )
        .bind(&file_hash)
        .bind(auth_event.unwrap().pubkey.to_hex())
        .fetch_one(&app_state.pool),
        false => query_as::<_, BlobDescriptor>("SELECT * FROM blob_descriptors WHERE sha256 = ?")
            .bind(&file_hash)
            .fetch_one(&app_state.pool),
    };

    // Execute the query against the database.
    let result = blob_descriptor_query.await;

    // Return the blob descriptor if it was found, a 404 if not found or a 500 if something else went wrong.
    let blob_descriptor = match result {
        Ok(descriptor) => descriptor,
        Err(Error::RowNotFound) => return build_not_found_error_response("Blob not found"),
        Err(e) => {
            eprintln!("{:?}", e);
            error!("Error fetching blob descriptor: {}", e);
            return build_internal_server_error_response(
                "Error fetching blob descriptor. Contact system admin.",
            );
        }
    };

    // Get blob from filesystem
    let file_contents =
        match get_blob_from_filesystem(&app_state.config.files_directory, &file_hash) {
            Ok(file_contents) => file_contents,
            Err(e) => {
                return match e {
                    utilities::file::Error::ReadFile => {
                        return build_internal_server_error_response("Failed to read blob");
                    }
                    utilities::file::Error::FileNotFound => {
                        return build_not_found_error_response("Blob not found");
                    }
                    utilities::file::Error::OpenFile => {
                        return build_internal_server_error_response("Failed to open blob");
                    }
                    _ => {
                        // TODO: This should never happen, maybe this handling needs some refactoring
                        build_internal_server_error_response(
                            "Something went wrong, contact system admin.",
                        )
                    }
                };
            }
        };

    let content_type = blob_descriptor
        .r#type
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
        StatusCode::OK.into_response()
    } else {
        build_not_found_error_response("File not found")
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
                return build_bad_request_error_response("Unable to parse public key in path");
            }
        };
        match auth_event {
            Some(ref auth_event) => {
                if auth_event.pubkey != path_public_key {
                    return build_unauthorized_error_response(
                        "Public key mismatch in authorization event and url path",
                    );
                }
                // Validate kind, expiration tag and t-tag (action)
                if let Err(error_msg) = validate_auth_event(auth_event, "list") {
                    return build_unauthorized_error_response(error_msg.to_string().as_str());
                }
            }
            None => {
                return build_unauthorized_error_response("Missing authorization event");
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

/// Perform checks for upload that can be done without the actual blob, like whether user is
/// allowed to upload files.
/// Returns the validated authentication event and content type on success, or an HTTP status code
/// and message on failure.
pub fn upload_blob_prechecks(
    app_state: &AppState,
    auth_event: Option<Event>,
    headers: &HeaderMap,
) -> Result<(Event, Option<String>), (StatusCode, String)> {
    // Validate that uploads are enabled
    if !app_state.config.upload.enabled {
        return Err((StatusCode::NOT_FOUND, "Uploads are disabled".to_string()));
    }

    // Get the auth event from HTTP headers
    let auth_event = match auth_event {
        Some(auth_event) => auth_event,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Authorization event required to upload a blob".to_string(),
            ));
        }
    };

    // Validate the authorization event
    match validate_auth_event(&auth_event, "upload") {
        Ok(_) => {}
        Err(error_msg) => {
            return Err((StatusCode::UNAUTHORIZED, error_msg.to_string()));
        }
    }

    // Check if public key is allowed to upload to the server
    if let Err(e) = is_public_key_allowed_to_upload(&app_state.config, &auth_event.pubkey) {
        return Err((StatusCode::UNAUTHORIZED, e.to_string()));
    }

    // Get the value of the Content-Length header, and check it against the allowed size.
    let content_length = headers
        .get("Content-Length")
        .map(|v| v.to_str().unwrap_or_default().to_string());

    // Only check validity if the header is present.
    // This is safe, because in the PUT /upload implementation the actual blob size is checked.
    if let Some(content_length) = content_length {
        if let Ok(content_length) = content_length.parse::<u64>() {
            let blob_size_in_mb = bytes_to_mb(content_length as f64);
            let max_size = app_state.config.upload.max_size;
            if blob_size_in_mb.ceil() > max_size {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Blob size is {} MB, max upload size is {} MB",
                        blob_size_in_mb, app_state.config.upload.max_size
                    ),
                ));
            }
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid Content-Length header".to_string(),
            ));
        };
    }

    // Get the value of the Content-Type header
    let content_type = headers
        .get("Content-Type")
        .map(|v| v.to_str().unwrap_or_default().to_string());

    // Validate the MIME type
    if let Err(e) = is_mime_type_allowed(&app_state.config, &content_type) {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string()));
    }

    Ok((auth_event, content_type))
}

pub async fn upload_blob_handler(
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (auth_event, content_type) = match upload_blob_prechecks(&app_state, auth_event, &headers) {
        Ok(auth_event) => auth_event,
        Err((code, message)) => {
            return build_error_response(code, message.as_str());
        }
    };

    // Validate the file hash against the hash defined in the authorization event
    let file_hash = match validate_file_hash(&auth_event, &body) {
        Ok(file_hash) => file_hash,
        Err(error_msg) => return build_bad_request_error_response(error_msg.to_string().as_str()),
    };

    // Check that the size of the blob does not exceed the limit set in the upload config
    // This check is already done for Content-Length header in upload_blob_prechecks, but here
    // we have the actual size of the blob, which is not necessarily the same.
    let blob_size_in_mb = bytes_to_mb(body.len() as f64);
    if blob_size_in_mb > app_state.config.upload.max_size {
        return build_bad_request_error_response(
            format!(
                "Blob size is {} MB, max upload size is {} MB",
                blob_size_in_mb, app_state.config.upload.max_size
            )
            .as_str(),
        );
    }

    // Write blob to file system
    let file_storage_dir = std::path::Path::new(&app_state.config.files_directory);

    match write_blob_to_file(file_storage_dir, &file_hash, body.clone()) {
        Ok(_) => {}
        Err(error_msg) => {
            return build_internal_server_error_response(error_msg.to_string().as_str());
        }
    }

    // Add an extension based on the MIME type
    let suffix = content_type
        .clone()
        .and_then(|mime_type| mime2ext(mime_type))
        .map(|ext| ".".to_string() + ext)
        .unwrap_or("".to_string());

    // Define Blob Descriptor
    let blob_descriptor = BlobDescriptor {
        url: format!("{}/{}{}", app_state.config.server_url, file_hash, suffix),
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
                error!("{}", e);
                return build_internal_server_error_response(
                    "Failed to update file reference count",
                );
            }
            Json(blob_descriptor).into_response()
        }
        Err(Error::Database(db_err)) if db_err.is_unique_violation() => {
            // Blob already uploaded by this public key.
            // Return the blob descriptor again, but without increasing the
            // reference count.
            Json(blob_descriptor).into_response()
        }
        Err(_) => build_internal_server_error_response("Failed to insert blob descriptor"),
    }
}

pub async fn upload_head_handler(
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
    headers: HeaderMap,
) -> impl IntoResponse {
    match upload_blob_prechecks(&app_state, auth_event, &headers) {
        Ok(_) => StatusCode::OK.into_response(),
        Err((code, message)) => build_error_response(code, message.as_str()),
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
            return build_unauthorized_error_response(
                "Authorization event required to delete a blob",
            );
        }
    };

    let (path_file_hash, _filetype) = split_filehash_and_filetype(file_hash);

    // Validate the authorization event
    match validate_auth_event(&auth_event, "delete") {
        Ok(_) => {}
        Err(error_msg) => {
            return build_unauthorized_error_response(error_msg.to_string().as_str());
        }
    }

    if let Err(err) = validate_auth_event_x(&auth_event, &path_file_hash) {
        return build_unauthorized_error_response(err.to_string().as_str());
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
            return build_not_found_error_response("Blob not found");
        }
        Err(e) => {
            error!("{}", e);
            return build_internal_server_error_response("Unexpected database error");
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
            return build_internal_server_error_response("Failed to delete blob descriptor");
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
            return build_internal_server_error_response("Failed to update reference count");
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
                return build_internal_server_error_response(error_msg.to_string().as_str());
            }
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

pub async fn mirror_blob_handler(
    State(app_state): State<AppState>,
    AuthHeader(auth_event): AuthHeader,
    Json(mirror_request): Json<MirrorRequest>,
) -> impl IntoResponse {
    // Return error if not enabled
    if !app_state.config.mirror.enable {
        return build_not_found_error_response("Mirror endpoint is not enabled");
    }

    // Get the auth event from HTTP headers
    let auth_event = match auth_event {
        Some(auth_event) => auth_event,
        None => {
            return build_unauthorized_error_response(
                "Authorization event required to upload a blob",
            );
        }
    };

    // Validate the authorization event
    match validate_auth_event(&auth_event, "upload") {
        Ok(_) => {}
        Err(error_msg) => {
            return build_unauthorized_error_response(error_msg.to_string().as_str());
        }
    }

    let client = Client::new();
    let response = match client.get(&mirror_request.url).send().await {
        Ok(response) => response,
        Err(_) => {
            return build_bad_request_error_response("Failed to download blob");
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
            return build_bad_request_error_response("Failed to read blob data");
        }
    };

    // Validate the file hash against the hash defined in the authorization event
    let file_hash = match validate_file_hash(&auth_event, &blob_data) {
        Ok(file_hash) => file_hash,
        Err(error_msg) => {
            return build_bad_request_error_response(error_msg.to_string().as_str());
        }
    };

    let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
    let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(_) => {
            return build_internal_server_error_response("Failed to write blob");
        }
    };

    if file.write_all(&blob_data).is_err() {
        return build_internal_server_error_response("Failed to write blob");
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
        Err(Error::Database(db_err)) if db_err.is_unique_violation() => {
            build_conflict_error_response("Blob already mirrored by this public key")
        }
        Err(_) => build_internal_server_error_response("Failed to insert blob descriptor"),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        Config, GetBlobConfig, ListConfig, MirrorConfig, UploadBlobConfig, UploadFilterListMode,
        UploadMimeTypeConfig, UploadPublicKeyConfig,
    };
    use crate::db::set_up_sqlite_db;
    use crate::handlers::{create_router, MirrorRequest};
    use crate::utilities::file::{create_directory_if_not_exists, write_blob_to_file};
    use crate::utilities::get_sha256_hash;
    use crate::{AppState, BlobDescriptor};
    use axum::body::{Body, Bytes};
    use axum::http;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use http_body_util::BodyExt;
    use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, SingleLetterTag, Tag, TagKind, Timestamp};
    use std::ops::Add;
    use std::path::Path;
    use std::process::exit;
    use std::time::SystemTime;
    use tempfile::TempDir;
    use tower::ServiceExt;
    use tracing::log::error;

    #[tokio::test]
    async fn get_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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
    async fn get_blob_handler_test_invalid_auth_event() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        // Activate auth requirement in get blob config
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().get(GetBlobConfig { require_auth: true })).await;
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

        // Create a test auth event with invalid kind
        let tags = vec![
            Tag::hashtag("get"),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::from_char('x').unwrap()),
                vec![file_hash.to_owned()],
            ),
            Tag::expiration(Timestamp::from(1643723400)),
        ];
        let auth_event = EventBuilder::new(Kind::Custom(1), "get".to_string(), tags)
            .sign_with_keys(&keypair)
            .unwrap();

        // Send a GET request to retrieve the blob.
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(&format!("/{}", file_hash))
                    .header(
                        "Authorization",
                        format!(
                            "Nostr {}",
                            base64::engine::general_purpose::STANDARD.encode(auth_event.as_json())
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that the response status code is Unauthorized (401).
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Authorization event has invalid kind: 1"
        )
    }

    #[tokio::test]
    async fn get_blob_handler_test_blob_not_found() {
        // Set up app config and axum router
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Create a test file hash that does not exist in the database
        let file_hash =
            "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553".to_string();

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

        // Verify that the response status code is Not Found (404).
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_blob_handler_test_invalid_hash_string() {
        // Set up app config and axum router
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Send a GET request to retrieve the blob.
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/an-invalid-hash")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that the response status code is Not Found (404).
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Blob not found"
        );
    }

    #[tokio::test]
    async fn has_blob_handler_test() {
        // Set up app config and axum router
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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
    async fn list_blobs_handler_test_invalid_auth_event() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        // Activate auth requirement in list config
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().list(ListConfig { require_auth: true })).await;
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

        // Create a test auth event with invalid kind
        let tags = vec![
            Tag::hashtag("list"),
            Tag::expiration(Timestamp::from(1643723400)),
        ];
        let auth_event = EventBuilder::new(Kind::Custom(1), "list".to_string(), tags)
            .sign_with_keys(&keypair)
            .unwrap();

        // Send a GET request to list blobs.
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(&format!("/list/{}", keypair.public_key().to_hex()))
                    .header(
                        "Authorization",
                        format!(
                            "Nostr {}",
                            base64::engine::general_purpose::STANDARD.encode(auth_event.as_json())
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that the response status code is Unauthorized (401).
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Authorization event has invalid kind: 1"
        );
    }

    #[tokio::test]
    async fn upload_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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
        assert_eq!(
            blob_descriptor.url,
            format!("https://example.com/{}.txt", file_hash)
        );

        let file_path = format!("{}/{}", app_state.config.files_directory, file_hash);
        assert!(Path::new(&file_path).exists());
    }

    #[tokio::test]
    async fn upload_blob_handler_test_mimetype_whitelist() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().upload(UploadBlobConfig {
                enabled: true,
                max_size: 1024.0,
                public_key_filter: UploadPublicKeyConfig {
                    enabled: false,
                    mode: UploadFilterListMode::Whitelist,
                    public_keys: vec![],
                },
                mimetype_filter: UploadMimeTypeConfig {
                    enabled: true,
                    mode: UploadFilterListMode::Whitelist,
                    mime_types: vec!["image/jpeg".to_string()],
                },
            }))
            .await;
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

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "MIME type text/plain not allowed to be uploaded to this server"
        );
    }

    #[tokio::test]
    async fn delete_blob_handler_test() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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

    #[tokio::test]
    async fn delete_blob_handler_test_invalid_auth_event() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
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

        // Create a test auth event with invalid kind
        let tags = vec![
            Tag::hashtag("delete"),
            Tag::expiration(Timestamp::from(1643723400)),
        ];
        let auth_event = EventBuilder::new(Kind::Custom(1), "delete".to_string(), tags)
            .sign_with_keys(&keypair)
            .unwrap();

        // Send DELETE request to our handler
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri(&format!("/{}", file_hash))
            .header(
                "Authorization",
                format!(
                    "Nostr {}",
                    base64::engine::general_purpose::STANDARD.encode(auth_event.as_json())
                ),
            )
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();

        // Verify expected HTTP response status
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Authorization event has invalid kind: 1"
        );
    }

    #[tokio::test]
    async fn mirror_blob_handler_test_invalid_auth_event() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        // Enable mirror endpoint
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().mirror(MirrorConfig { enable: true })).await;
        let app = create_router(app_state.clone()).await;

        // Create a test auth event with invalid kind
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(1643723400)),
        ];
        let auth_event = EventBuilder::new(Kind::Custom(1), "upload".to_string(), tags)
            .sign_with_keys(&keypair)
            .unwrap();

        let mirror_request = MirrorRequest {
            url: "https://example.com/blob".to_string(),
        };

        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/mirror")
            .header(
                "Authorization",
                format!(
                    "Nostr {}",
                    base64::engine::general_purpose::STANDARD.encode(auth_event.as_json())
                ),
            )
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&mirror_request).unwrap())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Authorization event has invalid kind: 1"
        );
    }

    #[tokio::test]
    async fn upload_head_handler_test_enabled() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .header("Content-Length", "1024")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn upload_head_handler_test_disabled() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().upload(UploadBlobConfig {
                enabled: false,
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
            }))
            .await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .header("Content-Length", "1024")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("X-Reason").unwrap(),
            "Uploads are disabled"
        );
    }

    #[tokio::test]
    async fn upload_head_handler_test_invalid_auth_event() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("get"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_event = EventBuilder::new(Kind::Custom(1), "upload".to_string(), tags)
            .sign_with_keys(&keypair)
            .unwrap();

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header(
                "Authorization",
                format!(
                    "Nostr {}",
                    base64::engine::general_purpose::STANDARD.encode(auth_event.as_json())
                ),
            )
            .header("Content-Type", "text/plain")
            .header("Content-Length", "1024")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("X-Reason")
                .unwrap()
                .to_str()
                .unwrap(),
            "Authorization event has invalid kind: 1"
        );
    }

    #[tokio::test]
    async fn upload_head_handler_test_invalid_content_length() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .header("Content-Length", "abc")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("X-Reason")
                .unwrap()
                .to_str()
                .unwrap(),
            "Invalid Content-Length header"
        );
    }

    #[tokio::test]
    async fn upload_head_handler_test_content_length_too_large() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) = set_up_app_state(ConfigBuilder::new()).await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .header("Content-Length", "10485760") // 10 MB
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("X-Reason")
                .unwrap()
                .to_str()
                .unwrap(),
            "Blob size is 10 MB, max upload size is 1 MB"
        );
    }

    #[tokio::test]
    async fn upload_head_handler_test_invalid_mime_type() {
        // Set up app config, keypair and axum router
        let keypair = Keys::generate();
        let (app_state, _temp_dir) =
            set_up_app_state(ConfigBuilder::new().upload(UploadBlobConfig {
                enabled: true,
                max_size: 1024.0,
                public_key_filter: UploadPublicKeyConfig {
                    enabled: false,
                    mode: UploadFilterListMode::Whitelist,
                    public_keys: vec![],
                },
                mimetype_filter: UploadMimeTypeConfig {
                    enabled: true,
                    mode: UploadFilterListMode::Whitelist,
                    mime_types: vec!["image/jpeg".to_string()],
                },
            }))
            .await;
        let app = create_router(app_state.clone()).await;

        // Create timestamp for expiration tag
        let timestamp = SystemTime::now()
            .add(core::time::Duration::new(3600, 0))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set up tags needed in auth header
        let tags = vec![
            Tag::hashtag("upload"),
            Tag::expiration(Timestamp::from(timestamp)),
        ];

        // Create the auth header
        let auth_header = generate_blossom_auth_header(keypair.clone(), "upload".to_string(), tags);

        let request = Request::builder()
            .method(http::Method::HEAD)
            .uri("/upload")
            .header("Authorization", format!("Nostr {}", auth_header))
            .header("Content-Type", "text/plain")
            .header("Content-Length", "1024")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response
                .headers()
                .get("X-Reason")
                .unwrap()
                .to_str()
                .unwrap(),
            "MIME type text/plain not allowed to be uploaded to this server"
        );
    }

    /// Sets up the application state for testing purposes.
    ///
    /// This function creates a temporary directory, sets up a SQLite database within it, and creates the necessary directories for storing files.
    ///
    /// # Parameters
    ///
    /// * `config_builder`: A `ConfigBuilder` instance used to construct the application configuration.
    ///
    /// # Returns
    ///
    /// A tuple containing the `AppState` instance and the `TempDir` instance used to create the temporary directory.
    ///
    /// # Panics
    ///
    /// If an error occurs while setting up the test database, this function will panic with an error message.
    ///
    async fn set_up_app_state(config_builder: ConfigBuilder) -> (AppState, TempDir) {
        let temp_dir = TempDir::new().unwrap();

        let db_url = format!("sqlite://{}", temp_dir.path().join("test.db").display());

        let pool_result = set_up_sqlite_db(db_url).await;

        let pool = match pool_result {
            Ok(pool) => pool,
            Err(e) => {
                eprintln!("Error setting up test DB: {:?}", e);
                panic!("Error setting up test DB");
            }
        };

        let files_dir = temp_dir.path().join("files").to_string_lossy().to_string();
        let config = config_builder
            .database_directory(temp_dir.path().display().to_string())
            .files_directory(files_dir)
            .build();

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

        (AppState { config, pool }, temp_dir)
    }

    fn generate_blossom_auth_header(keys: Keys, action: String, tags: Vec<Tag>) -> String {
        let json_event = EventBuilder::new(Kind::Custom(24242), action, tags)
            .sign_with_keys(&keys)
            .unwrap()
            .as_json();
        base64::engine::general_purpose::STANDARD.encode(json_event)
    }

    /// A builder for creating a `Config` instance.
    ///
    /// This builder allows you to set individual fields of the `Config` struct,
    /// and then build a complete `Config` instance with default values for any
    /// fields that were not explicitly set. The goal of this builder is to make
    /// it easy to create a server config for test purposes while maintaining
    /// clean and easy to read code.
    ///
    /// # Example
    ///
    /// ```
    /// let config = ConfigBuilder::new()
    ///     .database_directory("/path/to/db".to_string())
    ///     .files_directory("/path/to/files".to_string())
    ///     .server_url("https://example.com".to_string())
    ///     .build();
    /// ```
    struct ConfigBuilder {
        database_directory: Option<String>,
        files_directory: Option<String>,
        server_url: Option<String>,
        host: Option<String>,
        get: Option<GetBlobConfig>,
        upload: Option<UploadBlobConfig>,
        list: Option<ListConfig>,
        mirror: Option<MirrorConfig>,
    }

    impl ConfigBuilder {
        /// Creates a new `ConfigBuilder` instance.
        fn new() -> Self {
            Self {
                database_directory: None,
                files_directory: None,
                server_url: None,
                host: None,
                get: None,
                upload: None,
                list: None,
                mirror: None,
            }
        }

        /// Sets the database directory.
        fn database_directory(mut self, dir: String) -> Self {
            self.database_directory = Some(dir);
            self
        }

        /// Sets the files directory.
        fn files_directory(mut self, dir: String) -> Self {
            self.files_directory = Some(dir);
            self
        }

        /// Sets the server URL.
        fn server_url(mut self, url: String) -> Self {
            self.server_url = Some(url);
            self
        }

        /// Sets the host.
        fn host(mut self, host: String) -> Self {
            self.host = Some(host);
            self
        }

        /// Sets the get blob config.
        fn get(mut self, get: GetBlobConfig) -> Self {
            self.get = Some(get);
            self
        }

        /// Sets the upload blob config.
        fn upload(mut self, upload: UploadBlobConfig) -> Self {
            self.upload = Some(upload);
            self
        }

        /// Sets the list config.
        fn list(mut self, list: ListConfig) -> Self {
            self.list = Some(list);
            self
        }

        /// Sets the mirror config.
        fn mirror(mut self, mirror: MirrorConfig) -> Self {
            self.mirror = Some(mirror);
            self
        }

        /// Builds a complete `Config` instance.
        ///
        /// This function takes the values set on the `ConfigBuilder` instance and uses them to create a
        /// `Config` instance. Any fields that were not explicitly set will be given default values.
        ///
        /// The default values are as follows:
        ///
        /// *   `database_directory`: "/tmp/cherryserver/db/"
        /// *   `files_directory`: "/tmp/cherryserver/files/"
        /// *   `server_url`: "https://example.com"
        /// *   `host`: "127.0.0.1:8080"
        /// *   `get`: `GetBlobConfig` with `require_auth` set to `false`
        /// *   `upload`: `UploadBlobConfig` with `enabled` set to `true`, `max_size` set to `1024.0`, and
        ///     default public key and MIME type filter configurations.
        /// *   `list`: `ListConfig` with `require_auth` set to `false`
        /// *   `mirror`: `MirrorConfig` with `enable` set to `false`
        ///
        /// # Returns
        ///
        /// A complete `Config` instance.
        fn build(self) -> Config {
            Config {
                database_directory: self
                    .database_directory
                    .unwrap_or_else(|| "/tmp/cherryserver/db/".to_string()),
                files_directory: self
                    .files_directory
                    .unwrap_or_else(|| "/tmp/cherryserver/files/".to_string()),
                server_url: self
                    .server_url
                    .unwrap_or_else(|| "https://example.com".to_string()),
                host: self.host.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
                get: self.get.unwrap_or_else(|| GetBlobConfig {
                    require_auth: false,
                }),
                upload: self.upload.unwrap_or_else(|| UploadBlobConfig {
                    enabled: true,
                    max_size: 1.0,
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
                }),
                list: self.list.unwrap_or_else(|| ListConfig {
                    require_auth: false,
                }),
                mirror: self
                    .mirror
                    .unwrap_or_else(|| MirrorConfig { enable: false }),
            }
        }
    }
}
