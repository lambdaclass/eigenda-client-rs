/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
}

type Type = &'static str;
type Reason = String; // We cannot use &'static str here because the error message may contain dynamic information.

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to cast {0}: {1}")]
    Cast(Type, Reason),
}

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Invalid blob length: {0}")]
    InvalidBlobLength(usize),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(usize),
}
