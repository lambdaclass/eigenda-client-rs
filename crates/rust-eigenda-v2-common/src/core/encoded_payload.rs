use ark_bn254::Fr;
use rust_kzg_bn254_primitives::helpers::to_fr_array;

use crate::ConversionError;

use super::{Payload, PayloadEncodingVersion, BYTES_PER_SYMBOL};

/// Accepts the length of a byte array, and returns the length that the array would be after
/// adding internal byte padding.
///
/// The value returned from this function will always be a multiple of [`BYTES_PER_SYMBOL`]
fn get_padded_data_length(data_length: usize) -> usize {
    let bytes_per_chunk = BYTES_PER_SYMBOL - 1;
    let mut chunk_count = data_length / bytes_per_chunk;

    if data_length % bytes_per_chunk != 0 {
        chunk_count += 1;
    }

    chunk_count * BYTES_PER_SYMBOL
}

/// Accepts an array of data, and returns the array after adding padding to be bn254 friendly.
fn pad_to_bn254(data: &[u8]) -> Vec<u8> {
    let bytes_per_chunk = BYTES_PER_SYMBOL - 1;
    let output_length = get_padded_data_length(data.len());
    let mut padded_output = vec![0u8; output_length];

    // pre-pad the input, so that it aligns to 31 bytes. This means that the internally padded result will automatically
    // align to 32 bytes. Doing this padding in advance simplifies the for loop.
    let required_pad = (bytes_per_chunk - data.len() % bytes_per_chunk) % bytes_per_chunk;
    let pre_padded_payload = [data, &vec![0u8; required_pad]].concat();

    for elem in 0..output_length / 32 {
        let zero_byte_index = elem * BYTES_PER_SYMBOL;
        padded_output[zero_byte_index] = 0x00;

        let destination_index = zero_byte_index + 1;
        let source_index = elem * bytes_per_chunk;

        let pre_padded_chunk = &pre_padded_payload[source_index..source_index + bytes_per_chunk];
        padded_output[destination_index..destination_index + bytes_per_chunk]
            .copy_from_slice(pre_padded_chunk);
    }

    padded_output
}

/// [`EncodedPayload`] represents a payload that has had an encoding applied to it.
///
/// Encoding Format:
///
/// The encoded payload consists of two parts:
///
/// 1. Header (32 bytes):
///    - Byte 0: Always 0x00 (reserved)
///    - Byte 1: Encoding Version byte (e.g., 0x00 for PayloadEncodingVersion::Zero)
///    - Bytes 2-5: Big-endian u32 representing the original payload length
///    - Bytes 6-31: Reserved (filled with 0x00)
///
/// 2. Data (multiple of 32 bytes):
///    Each 32-byte chunk contains:
///    - Byte 0: 0x00 (padding byte to ensure the data is in valid field element range)
///    - Bytes 1-31: 31 bytes of actual payload data (or padding for the last chunk)
///
/// The padding ensures that all data is compatible with the bn254 curve's field element
/// limitations, as each 32-byte segment represents a field element.
#[derive(Debug, PartialEq)]
pub struct EncodedPayload {
    /// the size of these bytes is guaranteed to be a multiple of 32
    pub bytes: Vec<u8>,
}

impl EncodedPayload {
    /// Creates a new [`EncodedPayload`] from a [`Payload`], performing the `PayloadEncodingVersion0` encoding.
    pub fn new(payload: &Payload) -> Result<EncodedPayload, ConversionError> {
        let mut header = [0u8; 32].to_vec();
        header[1] = PayloadEncodingVersion::Zero as u8;

        let payload_bytes: Vec<u8> = payload.serialize();

        // add payload length to the header
        let payload_length: u32 = payload_bytes.len() as u32;
        header[2..6].copy_from_slice(&payload_length.to_be_bytes());

        // encode payload modulo bn254, and align to 32 bytes
        let encoded_data = pad_to_bn254(&payload_bytes);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&encoded_data);

        Ok(EncodedPayload { bytes })
    }

    /// Converts the encoded payload to an array of field elements.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        to_fr_array(&self.bytes)
    }
}
