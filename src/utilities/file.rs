use std::fmt::Formatter;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use axum::body::Bytes;
use tracing::log::{debug, error};

#[derive(Debug)]
pub enum Error {
    CreateDirectory(io::Error),
    CreateFile,
    WriteFile,
    DeleteFile,
    ReadFile,
    FileNotFound,
    OpenFile,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::CreateDirectory(e) => write!(f, "{}", e),
            Error::CreateFile => write!(f, "Unable to create new file"),
            Error::WriteFile => write!(f, "Unable to write blob to file"),
            Error::DeleteFile => write!(f, "Unable to delete blob"),
            Error::ReadFile => write!(f, "Unable to read blob"),
            Error::FileNotFound => write!(f, "Blob not found"),
            Error::OpenFile => write!(f, "Unable to open file"),
        }
    }
}

pub fn create_directory_if_not_exists(directory_path: &str) -> Result<(), Error> {
    if !Path::new(directory_path).exists() {
        // Config file directory doesn't exist, create a new one
        debug!("Dir not found, creating new dir at {}", directory_path);
        fs::create_dir_all(directory_path).map_err(Error::CreateDirectory)?;
    }
    Ok(())
}

pub fn get_blob_from_filesystem(
    directory_path: &String,
    file_name: &String,
) -> Result<Vec<u8>, Error> {
    let file_path = format!("{}/{}", directory_path, file_name);
    if !PathBuf::from(&file_path).exists() {
        return Err(Error::FileNotFound);
    };

    let mut file = match File::open(&file_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Unable to open file: {}", e);
            return Err(Error::OpenFile);
        }
    };

    let mut contents = Vec::new();
    match file.read_to_end(&mut contents) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            return Err(Error::ReadFile);
        }
    }

    Ok(contents)
}

pub fn write_blob_to_file(
    directory_path: &Path,
    filename: &String,
    body: Bytes,
) -> Result<(), Error> {
    let full_path = directory_path.join(filename);

    let mut file = match File::create(full_path) {
        Ok(file) => file,
        Err(e) => {
            error!("{}", e);
            return Err(Error::CreateFile);
        }
    };

    match file.write_all(&body) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            return Err(Error::WriteFile);
        }
    }

    Ok(())
}

pub fn delete_blob_from_filesystem(
    directory_path: &String,
    file_name: &String,
) -> Result<(), Error> {
    let file_path = format!("{}/{}", directory_path, file_name);
    if let Err(e) = fs::remove_file(file_path) {
        error!("{}", e);
        return Err(Error::DeleteFile);
    };
    Ok(())
}
