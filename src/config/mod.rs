use serde::Deserialize;
use std::fmt::Formatter;
use std::fs::File;
use std::io::Read;
use std::{fmt, io};

#[derive(Clone, Deserialize)]
pub struct Config {
    pub database_directory: String,
    pub files_directory: String,
    pub hostname: String,
    pub get: GetBlobConfig,
    pub upload: UploadBlobConfig,
    pub list: ListConfig,
    pub mirror: MirrorConfig,
}

#[derive(Clone, Deserialize)]
pub struct GetBlobConfig {
    pub require_auth: bool,
}

#[derive(Clone, Deserialize)]
pub struct UploadBlobConfig {
    pub enabled: bool,
    pub max_size: f64,
    pub public_key_filter: UploadPublicKeyConfig,
    pub mimetype_filter: UploadMimeTypeConfig,
}

#[derive(Clone, Deserialize)]
pub struct UploadPublicKeyConfig {
    pub enabled: bool,
    pub mode: UploadFilterListMode,
    pub public_keys: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub struct UploadMimeTypeConfig {
    pub enabled: bool,
    pub mode: UploadFilterListMode,
    pub mime_types: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub enum UploadFilterListMode {
    Whitelist,
    Blacklist,
}

#[derive(Clone, Deserialize)]
pub struct ListConfig {
    pub require_auth: bool,
}

#[derive(Clone, Deserialize)]
pub struct MirrorConfig {
    pub enable: bool,
}

#[derive(Debug)]
pub enum ConfigError {
    FileOpen(io::Error),
    FileRead(io::Error),
    TomlParseError(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::FileOpen(e) => write!(f, "failed to open config file: {}", e),
            ConfigError::FileRead(e) => write!(f, "failed to read config file: {}", e),
            ConfigError::TomlParseError(e) => write!(f, "failed to parse config file: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load_from_file_path(file_path: &str) -> Result<Self, ConfigError> {
        let mut file = File::open(file_path).map_err(ConfigError::FileOpen)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(ConfigError::FileRead)?;
        toml::from_str(&contents).map_err(ConfigError::TomlParseError)
    }
}
