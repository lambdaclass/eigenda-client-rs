use ethabi::{Address, ParamType, Token};

use crate::{core::eigenda_cert::{self, EigenDACert}, errors::EigenClientError, eth_client::EthClient};

/// Trait that defines the methods for the ethclient used by the verifier, needed in order to mock it for tests
#[async_trait::async_trait]
pub(crate) trait CertVerifierClient: Sync + Send + std::fmt::Debug {
    /// Request to the EigenDA service manager contract
    /// the batch metadata hash for a given batch id
    async fn verify_cert_v2(
        &self,
        eigenda_cert: &EigenDACert,
    ) -> Result<(), EigenClientError>;
}

#[async_trait::async_trait]
impl CertVerifierClient for EthClient {
    async fn verify_cert_v2(
        &self,
        eigenda_cert: &EigenDACert,
    ) -> Result<(), EigenClientError> {
        let reference_block_number = eigenda_cert.batch_header.reference_block_number;
        let func_selector =
            ethabi::short_signature("verifyCertV2", &[
                ParamType::Tuple(vec![
                    ParamType::FixedBytes(32),
                    ParamType::Uint(32),
                ]), // batch_header
                ParamType::Tuple(vec![
                    ParamType::Tuple(vec![
                        ParamType::Tuple(vec![
                            ParamType::Uint(16),
                            ParamType::Bytes,
                            ParamType::Tuple(vec![
                                ParamType::Tuple(vec![
                                    ParamType::Uint(256),
                                    ParamType::Uint(256)
                                ]), // commitment
                                ParamType::Tuple(vec![
                                    ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                                ]), // length commitment
                                ParamType::Tuple(vec![
                                    ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                                ]), // length proof
                                ParamType::Uint(32),
                            ]), // blob_commitment
                            ParamType::FixedBytes(32),
                        ]), // blob_header
                        ParamType::Bytes,
                        ParamType::Array(Box::new(ParamType::Uint(32))),
                    ]), // blob_certificate
                    ParamType::Uint(32),
                    ParamType::Bytes,
                ]), // blob_inclusion_info
                ParamType::Tuple(vec![
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]))),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]))),
                    ParamType::Tuple(vec![
                        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)
                    ]),
                    ParamType::Tuple(vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256)
                    ]),
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Uint(32))),
                    ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::Uint(32)),))),
                ]), // non_signer_stakes_and_signature
                ParamType::Bytes,
            ]);
        let mut data = func_selector.to_vec();
        data.append(&mut ethabi::encode(&eigenda_cert.batch_header.to_tokens()));
        data.append(&mut ethabi::encode(&eigenda_cert.blob_inclusion_info.to_tokens()));
        data.append(&mut ethabi::encode(&eigenda_cert.non_signer_stakes_and_signature.to_tokens()));
        data.append(&mut ethabi::encode(&[Token::Bytes(eigenda_cert.signed_quorum_numbers.clone())]));

        let res = self
            .call(
                self.cert_verifier_addr,
                bytes::Bytes::copy_from_slice(&data),
                Some(reference_block_number as u64),
            )
            .await
            .map_err(EigenClientError::EthClient)?;
        println!("Response: {:?}", res);

        Ok(())
    }
}

struct Verifier<T: CertVerifierClient> {
    eth_client: T,
}

impl<T: CertVerifierClient> Verifier<T> {
    pub async fn verify_cert_v2(&self, eigenda_cert: &EigenDACert) -> Result<(), EigenClientError> {
        self.eth_client.verify_cert_v2(eigenda_cert).await
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::utils::SecretUrl;

    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use url::Url;

    fn get_test_eigenda_cert() -> EigenDACert {
        // Create a test EigenDACert object with dummy data
        EigenDACert {
            batch_header: eigenda_cert::BatchHeaderV2 {
                batch_root: [0; 32],
                reference_block_number: 0,
            },
            blob_inclusion_info: eigenda_cert::BlobInclusionInfo {
                blob_certificate : eigenda_cert::BlobCertificate {
                    blob_header: eigenda_cert::BlobHeader {
                        version: 0,
                        quorum_numbers: vec![0; 32],
                        commitment : eigenda_cert::BlobCommitment {
                            commitment: eigenda_cert::G1Commitment { x: vec![0;32], y: vec![0;32] },
                            length_commitment: eigenda_cert::G2Commitment { x_a0: vec![0;32], x_a1: vec![0;32], y_a0: vec![0;32], y_a1: vec![0;32] },
                            length_proof: eigenda_cert::G2Commitment { x_a0: vec![0;32], x_a1: vec![0;32], y_a0: vec![0;32], y_a1: vec![0;32] },
                            length : 0,
                        },
                        payment_header_hash : [0; 32],
                    },
                    signature: vec![0; 32],
                    relay_keys: vec![0; 32],
                },
                blob_index: 0,
                inclusion_proof: vec![0; 32],
            },
            non_signer_stakes_and_signature: eigenda_cert::NonSignerStakesAndSignature {
                non_signer_quorum_bitmap_indices: vec![0; 32],
                non_signer_pubkeys: vec![G1Affine::identity(); 32],
                quorum_apks: vec![G1Affine::identity(); 32],
                apk_g2: G2Affine::identity(),
                sigma: G1Affine::identity(),
                quorum_apk_indices: vec![0; 32],
                total_stake_indices: vec![0; 32],
                non_signer_stake_indices: vec![vec![0; 32]; 32],
            },
            signed_quorum_numbers: vec![0; 32],
        }
    }

    #[tokio::test]
    async fn test_verify_cert_v2_fails() {
        let eth_client = EthClient::new(SecretUrl::new(Url::from_str("http://localhost:8545").unwrap()), Address::from_str("0x0000000000000000000000000000000000000000").unwrap());
        let eigenda_cert = get_test_eigenda_cert();

        let verifier = Verifier { eth_client };

        let result = verifier.verify_cert_v2(&eigenda_cert).await;

        assert!(result.is_err());
    }
}
