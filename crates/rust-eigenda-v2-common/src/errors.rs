/// Errors specific to the EigenDA certificate
#[derive(Debug, thiserror::Error)]
pub enum EigenDACertError {
    #[error("Serialization failed for EigenDA certificate {0}")]
    SerializationError(String),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse G1 point: {0}")]
    G1Point(String),
    #[error("Failed to parse G2 point: {0}")]
    G2Point(String),
    #[error(transparent)]
    ArkSerialization(#[from] ArkSerializationError),
}

/// Errors specific to Arkworks serialization
/// Rewritten to avoid compatibility issues when used directly
/// https://docs.rs/ark-serialize/latest/src/ark_serialize/error.rs.html
#[derive(Debug, thiserror::Error)]
pub enum ArkSerializationError {
    /// During serialization, we didn't have enough space to write extra info.
    #[error("Not enough space to write extra info")]
    NotEnoughSpace,
    /// During serialization, the data was invalid.
    #[error("Invalid data")]
    InvalidData,
    /// During serialization, non-empty flags were given where none were
    /// expected.
    #[error("Unexpected flags")]
    UnexpectedFlags,
    /// During serialization, we countered an I/O error.
    #[error("IO error")]
    IoError,
}

impl From<ark_serialize::SerializationError> for ArkSerializationError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        match value {
            ark_serialize::SerializationError::NotEnoughSpace => Self::NotEnoughSpace,
            ark_serialize::SerializationError::InvalidData => Self::InvalidData,
            ark_serialize::SerializationError::UnexpectedFlags => Self::UnexpectedFlags,
            ark_serialize::SerializationError::IoError(_) => Self::IoError,
        }
    }
}
