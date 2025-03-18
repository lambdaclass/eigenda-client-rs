use ark_bn254::Fr;

use super::payload::Payload;

pub struct EncodedPayload {
    /// the size of these bytes is guaranteed to be a multiple of 32
    bytes: Vec<u8>,
}

impl EncodedPayload {
    pub fn encoded_payload_from_elements(
        payload_elements: Vec<Fr>,
        max_possible_payload_length: usize,
    ) -> EncodedPayload {
        // todo
        EncodedPayload { bytes: vec![] }
    }

    pub fn decode(&self) -> Payload {
        // todo
        Payload { bytes: vec![] }
    }
}
