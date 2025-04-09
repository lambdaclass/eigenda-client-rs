use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_bn254::G1Affine;
use ark_ff::Zero;
use hex::ToHex;
use rust_kzg_bn254_primitives::helpers::to_fr_array;

use crate::accountant::Accountant;
use crate::core::eigenda_cert::{BlobCommitment, BlobHeader, PaymentHeader};
use crate::core::{BlobKey, BlobRequestSigner, LocalBlobRequestSigner};
use crate::generated::common::v2::{
    BlobHeader as BlobHeaderProto, PaymentHeader as PaymentHeaderProto,
};
use crate::generated::common::BlobCommitment as BlobCommitmentProto;
use crate::generated::disperser::v2::{
    disperser_client, BlobCommitmentReply, BlobCommitmentRequest, BlobStatus, BlobStatusReply,
    BlobStatusRequest, DisperseBlobRequest, GetPaymentStateReply, GetPaymentStateRequest,
};
use crate::prover::Prover;

const MAX_QUORUM_ID: u8 = 255;
const BYTES_PER_SYMBOL: usize = 32;

#[derive(Debug)]
pub struct DisperserClientConfig {
    host: String,
    port: u16,
    timeout: Duration,
    use_secure_grpc_flag: bool,
    max_retrieve_blob_size_bytes: u64,
}

impl DisperserClientConfig {
    pub fn new(
        host: String,
        port: u16,
        use_secure_grpc_flag: bool,
        timeout: Duration,
        max_retrieve_blob_size_bytes: u64,
    ) -> Result<Self, String> {
        if host.is_empty() {
            return Err("host cannot be empty".to_string());
        }

        if timeout.is_zero() {
            return Err("timeout cannot be zero".to_string());
        }

        if max_retrieve_blob_size_bytes.is_zero() {
            return Err("max_retrieve_blob_size_bytes cannot be zero".to_string());
        }

        Ok(Self {
            host,
            port,
            use_secure_grpc_flag,
            timeout,
            max_retrieve_blob_size_bytes,
        })
    }
}

pub struct DisperserClient {
    config: DisperserClientConfig,
    signer: LocalBlobRequestSigner,
    rpc_client: disperser_client::DisperserClient<tonic::transport::Channel>,
    prover: Prover,
    accountant: Accountant,
}

// todo: add locks
impl DisperserClient {
    pub async fn new(
        config: DisperserClientConfig,
        signer: LocalBlobRequestSigner,
        rpc_client: disperser_client::DisperserClient<tonic::transport::Channel>,
        prover: Prover,
        accountant: Accountant,
    ) -> Self {
        let mut disperser = Self {
            config,
            signer,
            rpc_client,
            prover,
            accountant,
        };
        disperser.populate_accountant().await.unwrap();
        disperser
    }

    //todo: error handling
    pub async fn disperse_blob(
        &mut self,
        data: &[u8],
        blob_version: u16,
        quorums: &[u8],
    ) -> Result<(BlobStatus, BlobKey), String> {
        if quorums.is_empty() {
            return Err("quorum numbers must be provided".to_string());
        }

        for quorum in quorums {
            if *quorum > MAX_QUORUM_ID {
                return Err("quorum number must be less than 256".to_string());
            }
        }

        let symbol_length =
            ((data.len() + BYTES_PER_SYMBOL - 1) / BYTES_PER_SYMBOL).next_power_of_two();
        let payment = self
            .accountant
            .account_blob(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                symbol_length as u64,
                quorums,
            )
            .unwrap();
        //to_fr_array(data); //doesn't return error so no need to do the check

        // if prover is null: //todo: prover not null
        let blob_commitment_reply = self.blob_commitment(data).await?;
        let Some(blob_commitment) = blob_commitment_reply.blob_commitment else {
            return Err("blob commitment is empty".to_string());
        };
        let core_blob_commitment: BlobCommitment = blob_commitment.clone().try_into().unwrap();
        if core_blob_commitment.length != symbol_length as u32 {
            return Err(format!(
                "blob commitment length {} does not match symbol length {}",
                core_blob_commitment.length, symbol_length
            ));
        }
        let account_id: String = payment.account_id.encode_hex();
        //todo: remove alloy and implement to checksum manually
        let account_id: String = alloy_primitives::Address::from_str(&account_id)
            .unwrap()
            .to_checksum(None);

        let blob_header = BlobHeader {
            version: blob_version,
            commitment: core_blob_commitment.clone(),
            quorum_numbers: quorums.to_vec(),
            payment_header_hash: PaymentHeader {
                account_id: account_id.clone(),
                timestamp: payment.timestamp,
                cumulative_payment: payment.cumulative_payment.to_signed_bytes_be(),
            }
            .hash()
            .unwrap(),
        };

        let signature = self.signer.sign(blob_header.clone())?;
        let disperse_request = DisperseBlobRequest {
            blob: data.to_vec(),
            blob_header: Some(BlobHeaderProto {
                version: blob_header.version as u32,
                commitment: Some(blob_commitment),
                quorum_numbers: quorums.to_vec().iter().map(|&x| x as u32).collect(),
                payment_header: Some(PaymentHeaderProto {
                    account_id: account_id,
                    timestamp: payment.timestamp,
                    cumulative_payment: payment.cumulative_payment.to_signed_bytes_be(),
                }),
            }),
            signature,
        };

        let reply = self
            .rpc_client
            .disperse_blob(disperse_request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))?;

        if blob_header.blob_key().unwrap().to_bytes().to_vec() != reply.blob_key {
            return Err("blob key mismatch".to_string());
        }

        Ok((
            BlobStatus::try_from(reply.result).unwrap(),
            blob_header.blob_key().unwrap(),
        ))
    }

    /// Populates the accountant with the payment state from the disperser.
    async fn populate_accountant(&mut self) -> Result<(), String> {
        let payment_state = self.payment_state().await?;
        self.accountant.set_payment_state(&payment_state)?;
        Ok(())
    }

    /// Returns the status of a blob with the given blob key.
    pub async fn blob_status(&mut self, blob_key: BlobKey) -> Result<BlobStatusReply, String> {
        let request = BlobStatusRequest {
            blob_key: blob_key.to_bytes().to_vec(),
        };

        self.rpc_client
            .get_blob_status(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }

    /// Returns the payment state of the disperser client
    pub async fn payment_state(&mut self) -> Result<GetPaymentStateReply, String> {
        let account_id = self.signer.account_id()?.encode_hex();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Failed to get current time")?
            .as_nanos();
        let signature = self.signer.sign_payment_state_request(timestamp as u64)?;
        let request = GetPaymentStateRequest {
            account_id,
            signature,
            timestamp: timestamp as u64,
        };

        self.rpc_client
            .get_payment_state(request)
            .await
            .map(|response: tonic::Response<GetPaymentStateReply>| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }

    pub async fn blob_commitment(&mut self, data: &[u8]) -> Result<BlobCommitmentReply, String> {
        let request = BlobCommitmentRequest {
            blob: data.to_vec(),
        };

        self.rpc_client
            .get_blob_commitment(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|status| format!("Failed RPC call: {}", status))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    use crate::{
        accountant::{Accountant, PeriodRecord},
        core::{LocalBlobRequestSigner, OnDemandPayment, ReservedPayment},
        disperser_client::DisperserClient,
        generated::disperser::v2::disperser_client,
        prover::Prover,
    };

    use super::DisperserClientConfig;

    use dotenv::dotenv;
    use std::env;

    #[tokio::test]
    async fn test_disperse() {
        dotenv().ok();

        // Set your private key in .env file
        let private_key: String =
            env::var("SIGNER_PRIVATE_KEY").expect("SIGNER_PRIVATE_KEY must be set");

        let config = DisperserClientConfig {
            host: "https://disperser-preprod-holesky.eigenda.xyz".to_string(),
            port: 443,
            use_secure_grpc_flag: false,
            timeout: std::time::Duration::new(5, 0),
            max_retrieve_blob_size_bytes: 1024 * 1024 * 10,
        };
        let signer = LocalBlobRequestSigner::new(&private_key).unwrap();
        let rpc_client = disperser_client::DisperserClient::connect(
            "https://disperser-preprod-holesky.eigenda.xyz:443",
        )
        .await
        .unwrap();
        let prover = Prover {};
        let accountant = Accountant {
            account_id: "0xD9309b3CF1B7DBF59f53461c2a66e2783dD1766f"
                .parse()
                .unwrap(),
            reservation: ReservedPayment {
                symbols_per_second: 0,
                start_timestamp: 0,
                end_timestamp: 0,
                quorum_numbers: vec![0, 1],
                quorum_splits: vec![50, 50],
            },
            on_demand: OnDemandPayment {
                cumulative_payment: BigInt::from(100),
            },
            reservation_window: 0,
            price_per_symbol: 1,
            min_num_symbols: 100,
            period_records: vec![],
            cumulative_payment: BigInt::from(0),
            num_bins: 3,
        };
        let mut client = DisperserClient::new(config, signer, rpc_client, prover, accountant).await;
        let data = vec![1, 2, 3, 4, 5];
        let blob_version = 0;
        let quorums = vec![0, 1];
        let result = client
            .disperse_blob(&data, blob_version, &quorums)
            .await
            .unwrap();
        println!("Disperse result: {:?}", result.0);
        println!("Blob key: {:?}", result.1);
    }
}
