use ark_bn254::Fr;

/// [`Blob`] is data that is dispersed on EigenDA.
///
/// A Blob is represented under the hood by an array of field elements, which represent a polynomial in coefficient form.
#[derive(Debug, PartialEq)]
pub struct Blob {
    pub coeff_polynomial: Vec<Fr>,
    /// blob_length_symbols must be a power of 2, and should match the blob_length claimed in the blob_commitment
    ///
    /// This value must be specified, rather than computed from the length of the coeff_polynomial, due to an edge case
    /// illustrated by the following example: imagine a user disperses a very small blob, only 64 bytes, and the last 40
    /// bytes are trailing zeros. When a different user fetches the blob from a relay, it's possible that the relay could
    /// truncate the trailing zeros. If we were to say that blob_length_symbols = next_power_of_2(len(coeff_polynomial)), then the
    /// user fetching and reconstructing this blob would determine that the blob length is 1 symbol, when it's actually 2.
    pub blob_length_symbols: usize,
}
