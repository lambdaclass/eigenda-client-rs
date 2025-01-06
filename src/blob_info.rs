use ethabi::Token;
use ethereum_types::U256;

use crate::errors::ConversionError;

use super::{
    common::G1Commitment as DisperserG1Commitment,
    disperser::{
        BatchHeader as DisperserBatchHeader, BatchMetadata as DisperserBatchMetadata,
        BlobHeader as DisperserBlobHeader, BlobInfo as DisperserBlobInfo,
        BlobQuorumParam as DisperserBlobQuorumParam,
        BlobVerificationProof as DisperserBlobVerificationProof,
    },
};

/// Internal of BlobInfo
/// Contains the KZG Commitment
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct G1Commitment {
    pub(crate) x: Vec<u8>,
    pub(crate) y: Vec<u8>,
}

impl From<DisperserG1Commitment> for G1Commitment {
    fn from(value: DisperserG1Commitment) -> Self {
        Self {
            x: value.x,
            y: value.y,
        }
    }
}

impl G1Commitment {
    fn into_tokens(&self) -> Vec<Token> {
        let x = Token::Uint(U256::from_big_endian(&self.x));
        let y = Token::Uint(U256::from_big_endian(&self.y));

        vec![x, y]
    }
}

/// Internal of BlobInfo
/// Contains data related to the blob quorums
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobQuorumParam {
    pub(crate) quorum_number: u32,
    pub(crate) adversary_threshold_percentage: u32,
    pub(crate) confirmation_threshold_percentage: u32,
    pub(crate) chunk_length: u32,
}

impl From<DisperserBlobQuorumParam> for BlobQuorumParam {
    fn from(value: DisperserBlobQuorumParam) -> Self {
        Self {
            quorum_number: value.quorum_number,
            adversary_threshold_percentage: value.adversary_threshold_percentage,
            confirmation_threshold_percentage: value.confirmation_threshold_percentage,
            chunk_length: value.chunk_length,
        }
    }
}

impl BlobQuorumParam {
    fn into_tokens(self) -> Vec<Token> {
        let quorum_number = Token::Uint(U256::from(self.quorum_number));
        let adversary_threshold_percentage =
            Token::Uint(U256::from(self.adversary_threshold_percentage));
        let confirmation_threshold_percentage =
            Token::Uint(U256::from(self.confirmation_threshold_percentage));
        let chunk_length = Token::Uint(U256::from(self.chunk_length));

        vec![
            quorum_number,
            adversary_threshold_percentage,
            confirmation_threshold_percentage,
            chunk_length,
        ]
    }
}

/// Internal of BlobInfo
/// Contains the blob header data
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobHeader {
    pub(crate) commitment: G1Commitment,
    pub(crate) data_length: u32,
    pub(crate) blob_quorum_params: Vec<BlobQuorumParam>,
}

impl TryFrom<DisperserBlobHeader> for BlobHeader {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobHeader) -> Result<Self, Self::Error> {
        let blob_quorum_params: Vec<BlobQuorumParam> = value
            .blob_quorum_params
            .iter()
            .map(|param| BlobQuorumParam::from(param.clone()))
            .collect();
        Ok(Self {
            commitment: G1Commitment::from(
                value
                    .commitment
                    .ok_or(ConversionError::NotPresent("BlobHeader".to_string()))?,
            ),
            data_length: value.data_length,
            blob_quorum_params,
        })
    }
}

impl BlobHeader {
    pub fn into_tokens(self) -> Vec<Token> {
        let commitment = self.commitment.into_tokens();
        let data_length = Token::Uint(U256::from(self.data_length));
        let blob_quorum_params = self
            .blob_quorum_params
            .into_iter()
            .map(|quorum| Token::Tuple(quorum.into_tokens()))
            .collect();

        vec![
            Token::Tuple(commitment),
            data_length,
            Token::Array(blob_quorum_params),
        ]
    }
}

/// Internal of BlobInfo
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BatchHeader {
    pub(crate) batch_root: Vec<u8>,
    pub(crate) quorum_numbers: Vec<u8>,
    pub(crate) quorum_signed_percentages: Vec<u8>,
    pub(crate) reference_block_number: u32,
}

impl From<DisperserBatchHeader> for BatchHeader {
    fn from(value: DisperserBatchHeader) -> Self {
        Self {
            batch_root: value.batch_root,
            quorum_numbers: value.quorum_numbers,
            quorum_signed_percentages: value.quorum_signed_percentages,
            reference_block_number: value.reference_block_number,
        }
    }
}

/// Internal of BlobInfo
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BatchMetadata {
    pub(crate) batch_header: BatchHeader,
    pub(crate) signatory_record_hash: Vec<u8>,
    pub(crate) fee: Vec<u8>,
    pub(crate) confirmation_block_number: u32,
    pub(crate) batch_header_hash: Vec<u8>,
}

impl TryFrom<DisperserBatchMetadata> for BatchMetadata {
    type Error = ConversionError;
    fn try_from(value: DisperserBatchMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            batch_header: BatchHeader::from(
                value
                    .batch_header
                    .ok_or(ConversionError::NotPresent("BatchMetadata".to_string()))?,
            ),
            signatory_record_hash: value.signatory_record_hash,
            fee: value.fee,
            confirmation_block_number: value.confirmation_block_number,
            batch_header_hash: value.batch_header_hash,
        })
    }
}

/// Internal of BlobInfo
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobVerificationProof {
    pub(crate) batch_id: u32,
    pub(crate) blob_index: u32,
    pub(crate) batch_medatada: BatchMetadata,
    pub(crate) inclusion_proof: Vec<u8>,
    pub(crate) quorum_indexes: Vec<u8>,
}

impl TryFrom<DisperserBlobVerificationProof> for BlobVerificationProof {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobVerificationProof) -> Result<Self, Self::Error> {
        Ok(Self {
            batch_id: value.batch_id,
            blob_index: value.blob_index,
            batch_medatada: BatchMetadata::try_from(value.batch_metadata.ok_or(
                ConversionError::NotPresent("BlobVerificationProof".to_string()),
            )?)?,
            inclusion_proof: value.inclusion_proof,
            quorum_indexes: value.quorum_indexes,
        })
    }
}

/// Data returned by the disperser when a blob is dispersed
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobInfo {
    pub(crate) blob_header: BlobHeader,
    pub(crate) blob_verification_proof: BlobVerificationProof,
}

impl TryFrom<DisperserBlobInfo> for BlobInfo {
    type Error = ConversionError;
    fn try_from(value: DisperserBlobInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blob_header: BlobHeader::try_from(
                value
                    .blob_header
                    .ok_or(ConversionError::NotPresent("BlobInfo".to_string()))?,
            )?,
            blob_verification_proof: BlobVerificationProof::try_from(
                value
                    .blob_verification_proof
                    .ok_or(ConversionError::NotPresent("BlobInfo".to_string()))?,
            )?,
        })
    }
}
