use super::blob::Blob;

/// Payload represents arbitrary user data, without any processing.
pub struct Payload {
    pub bytes: Vec<u8>,
}

impl Payload {
    pub fn to_blob(&self) -> Blob {
        // todo
        Blob { coeff_polynomial: vec![], blob_length_symbols: 0 }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // todo
        vec![]
    }
}
