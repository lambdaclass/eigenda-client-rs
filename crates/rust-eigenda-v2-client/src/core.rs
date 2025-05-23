mod blob;
mod blob_key;
pub mod eigenda_cert;
mod encoded_payload;
mod payload;
mod payment;

pub use blob::Blob;
pub use blob_key::BlobKey;
pub use encoded_payload::EncodedPayload;
pub use payload::Payload;
pub use payment::{OnDemandPayment, PaymentMetadata, PaymentStateRequest, ReservedPayment};

pub(crate) const BYTES_PER_SYMBOL: usize = 32;

/// Payload encoding version
#[derive(Debug, PartialEq)]
pub enum PayloadEncodingVersion {
    Zero = 0,
}

/// The form of a payload dictates what conversion, if any, must be performed when creating a blob from the payload.
#[derive(Clone, Copy, Debug)]
pub enum PayloadForm {
    /// Evaluation form, where the payload is in evaluation form.
    Eval,
    /// Coefficient form, where the payload is in coefficient form.
    Coeff,
}
