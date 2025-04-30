mod blob_key;
pub mod eigenda_cert;
mod payment;

pub use blob_key::BlobKey;
pub use payment::{OnDemandPayment, PaymentMetadata, ReservedPayment, PaymentStateRequest};

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
