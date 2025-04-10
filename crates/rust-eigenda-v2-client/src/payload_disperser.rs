use crate::{cert_verifier::CertVerifier, core::{eigenda_cert::{BlobCertificate, EigenDACert}, BlobKey, Payload, PayloadForm}, disperser_client::{DisperserClient, DisperserClientConfig}, generated::disperser::v2::{BlobStatus, BlobStatusReply}};

pub(crate) struct PayloadDisperserConfig {
    polynomial_form: PayloadForm,
    blob_version: u16,
}

pub(crate) struct PayloadDisperser {
    config: PayloadDisperserConfig,
    disperser_client: DisperserClient,
    cert_verifier: CertVerifier,
}

impl PayloadDisperser {
    pub async fn new(disperser_config: DisperserClientConfig, payload_config: PayloadDisperserConfig) -> Result<Self,String> {
        let disperser_client = DisperserClient::new(disperser_config).await.unwrap();
        Ok(PayloadDisperser {
            disperser_client,
            config: payload_config
        })
    }
    //todo error handling
    pub async fn send_payload(&self, payload: Payload) -> Result<BlobKey, String> {
        let blob = payload.to_blob(self.config.polynomial_form).unwrap();

        // required_quorums = certVerifier.GetQuorumNumbersRequired

        let (blob_status, blob_key) = self.disperser_client.disperse_blob(&blob.serialize(), self.config.blob_version, required_quorums).await.unwrap();

        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => {
                return Err("Blob status is unknown or failed".to_string());
            }
            BlobStatus::Complete | BlobStatus::Encoded | BlobStatus::GatheringSignatures | BlobStatus::Queued => {
                
            }
        }
        Ok(blob_key)
    }

    pub async fn get_inclusion_data(&mut self, blob_key: &BlobKey) -> Result<Option<EigenDACert>, String> {
        let status = self.disperser_client.blob_status(blob_key).await.unwrap();

        let blob_status = BlobStatus::try_from(status.status).unwrap();
        match blob_status {
            BlobStatus::Unknown | BlobStatus::Failed => {
                Err("Blob status is unknown or failed".to_string())
            }
            BlobStatus::Encoded | BlobStatus::GatheringSignatures | BlobStatus::Queued => {
                Ok(None)
            }
            BlobStatus::Complete => {
                let eigenda_cert = self.build_eigenda_cert(blob_key, status).await.unwrap();
                //todo verify_cert_v2
                Ok(Some(eigenda_cert))
            }
        }
    }

    pub async fn build_eigenda_cert(&self, blob_key: &BlobKey, status: BlobStatusReply) -> Result<EigenDACert, String> {
        let non_signer_stakes_and_signature = self.cert_verifier.get_non_signer_stakes_and_signature(&status.signed_batch).await.unwrap();

        EigenDACert::new(status, non_signer_stakes_and_signature)

    }
}
