use ark_bn254::{Fr, G1Affine};

/// Errors specific to the EigenDA certificate
#[derive(Debug, thiserror::Error)]
pub enum EigenDACertError {
    #[error("Serialization failed for EigenDA certificate {0}")]
    SerializationError(String),
}

/// Errors specific to the Blob type
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Invalid blob length: {0}")]
    InvalidBlobLength(usize),
    #[error("Blob length is zero")]
    InvalidBlobLengthZero,
    #[error("Blob length is not a power of two")]
    InvalidBlobLengthNotPowerOfTwo(usize),
    #[error("Mismatch between commitment ({0}) and blob ({1})")]
    CommitmentAndBlobLengthMismatch(usize, usize),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(usize),
    #[error("Invalid quorum number: {0}")]
    InvalidQuorumNumber(u32),
    #[error("Missing field: {0}")]
    MissingField(String),
    #[error(transparent)]
    Bn254(#[from] Bn254Error),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to parse G1 point: {0}")]
    G1Point(String),
    #[error("Failed to parse G2 point: {0}")]
    G2Point(String),
    #[error(transparent)]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
    #[error("Failed to convert polynomial: {0}")]
    Poly(String),
    #[error("Failed to parse payload: {0}")]
    Payload(String),
    #[error("Failed to parse encoded payload: {0}")]
    EncodedPayload(String),
}

/// Errors related to the BN254 and its points
#[derive(Debug, thiserror::Error)]
pub enum Bn254Error {
    #[error("Insufficient SRS in memory: have {0}, need {1}")]
    InsufficientSrsInMemory(usize, usize),
    #[error("Failed calculating multi scalar multiplication on base {:?} with scalars {:?}", .0, .1)]
    FailedComputingMSM(Vec<G1Affine>, Vec<Fr>),
}
