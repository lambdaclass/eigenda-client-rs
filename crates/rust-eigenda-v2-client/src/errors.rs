/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Blob(#[from] BlobError),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse payload: {0}")]
    Payload(String),
    #[error("Failed to parse encoded payload: {0}")]
    EncodedPayload(String),
    #[error("Failed to parse polynomial: {0}")]
    Poly(String),
}

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Invalid blob length: {0}")]
    InvalidBlobLength(usize),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(usize),
}
