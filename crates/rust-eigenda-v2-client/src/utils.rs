use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

/// Converts an eval_poly to a coeff_poly, using the IFFT operation
///
/// blob_length_symbols is required, to be able to choose the correct parameters when performing FFT
pub(crate) fn eval_to_coeff_poly(
    eval_poly: Vec<Fr>,
    blob_length_symbols: usize,
) -> Result<Vec<Fr>, String> {
    Ok(
        GeneralEvaluationDomain::<Fr>::new(blob_length_symbols)
            .ok_or("Failed to create domain")?
            .ifft(&eval_poly),
    )
}
