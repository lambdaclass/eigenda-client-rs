use std::u16;

use ark_bn254::{G1Affine, G2Affine};
use ethabi::Token;
use ethereum_types::U256;
use rust_kzg_bn254_primitives::traits::ReadPointFromBytes;
use tiny_keccak::{Hasher, Keccak};

use crate::generated::disperser::v2::BlobStatusReply;

use crate::generated::{
    common::{
        v2::{
            BatchHeader as ProtoBatchHeader, BlobCertificate as ProtoBlobCertificate,
            BlobHeader as ProtoBlobHeader, PaymentHeader as ProtoPaymentHeader,
        },
        BlobCommitment as ProtoBlobCommitment,
    },
    disperser::v2::BlobInclusionInfo as ProtoBlobInclusionInfo,
};

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct PaymentHeader {
    pub(crate) account_id: String,
    pub(crate) timestamp: i64,
    pub(crate) cumulative_payment: Vec<u8>,
}

impl From<ProtoPaymentHeader> for PaymentHeader {
    fn from(value: ProtoPaymentHeader) -> Self {
        PaymentHeader {
            account_id: value.account_id,
            timestamp: value.timestamp,
            cumulative_payment: value.cumulative_payment,
        }
    }
}

impl PaymentHeader {
    pub fn hash(&self) -> [u8; 32] {
        let cumulative_payment = U256::try_from(self.cumulative_payment.as_slice()).unwrap();
        let token = Token::Tuple(vec![
            Token::String(self.account_id.clone()),
            Token::Int(self.timestamp.into()),
            Token::Uint(cumulative_payment),
        ]);

        let encoded = ethabi::encode(&[token]);

        let mut hasher = Keccak::v256();
        hasher.update(&encoded);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        hash
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobCommitment {
    commitment: G1Affine,
    length_commitment: G2Affine,
    length_proof: G2Affine,
    length: u32,
}

impl From<ProtoBlobCommitment> for BlobCommitment {
    fn from(value: ProtoBlobCommitment) -> Self {
        let commitment = G1Affine::read_point_from_bytes_be(&value.commitment).unwrap();
        let length_commitment = G2Affine::default(); // G2Affine::deserialize(value.length_commitment); TODO: Implement deserialization
        let length_proof = G2Affine::default(); // G2Affine::deserialize(value.length_proof.unwrap()); TODO: Implement deserialization
        let length = value.length;

        Self {
            commitment,
            length_commitment,
            length_proof,
            length,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct V2BlobHeader {
    version: u16,
    quorum_numbers: Vec<u8>,
    commitment: BlobCommitment,
    payment_header_hash: [u8; 32],
}

impl From<ProtoBlobHeader> for V2BlobHeader {
    fn from(value: ProtoBlobHeader) -> Self {
        let version: u16 = match value.version.try_into() {
            Ok(version) => version,
            Err(_) => panic!("Version is too large"), // TODO: handle error
        };

        let mut quorum_numbers: Vec<u8> = Vec::new();
        for number in value.quorum_numbers.iter() {
            quorum_numbers.push((*number).try_into().unwrap()); // TODO: handle error
        }

        let commitment = BlobCommitment::from(value.commitment.unwrap()); // TODO: handle error

        // let payment_header_hash = vec![0u8; 32].try_into().unwrap(); // TODO: handle error
        let payment_header_hash = PaymentHeader::from(value.payment_header.unwrap()).hash();

        Self {
            version,
            quorum_numbers,
            commitment,
            payment_header_hash,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct V2BlobCertificate {
    blob_header: V2BlobHeader,
    signature: Vec<u8>,
    relay_keys: Vec<u32>,
}

impl From<ProtoBlobCertificate> for V2BlobCertificate {
    fn from(value: ProtoBlobCertificate) -> Self {
        Self {
            blob_header: V2BlobHeader::from(value.blob_header.unwrap()),
            signature: value.signature,
            relay_keys: value.relay_keys,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BlobInclusionInfo {
    blob_certificate: V2BlobCertificate,
    blob_index: u32,
    inclusion_proof: Vec<u8>,
}

impl From<ProtoBlobInclusionInfo> for BlobInclusionInfo {
    fn from(value: ProtoBlobInclusionInfo) -> Self {
        Self {
            blob_certificate: V2BlobCertificate::from(value.blob_certificate.unwrap()), // TODO: handle error (change to try_from)
            blob_index: value.blob_index,
            inclusion_proof: value.inclusion_proof,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct BatchHeaderV2 {
    batch_root: [u8; 32],
    reference_block_number: u32,
}

impl From<ProtoBatchHeader> for BatchHeaderV2 {
    fn from(value: ProtoBatchHeader) -> Self {
        let batch_root: [u8; 32] = value.batch_root.try_into().unwrap(); // TODO: handle error (change to try_from)
        let reference_block_number = value.reference_block_number.try_into().unwrap(); // TODO: handle error (change to try_from)
        Self {
            batch_root,
            reference_block_number,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct NonSignerStakesAndSignature {
    non_signer_quorum_bitmap_indices: Vec<u32>,
    non_signer_pubkeys: Vec<G1Affine>,
    quorum_apks: Vec<G1Affine>,
    apk_g2: G2Affine,
    sigma: G1Affine,
    quorum_apk_indices: Vec<u32>,
    total_stake_indices: Vec<u32>,
    non_signer_stake_indices: Vec<Vec<u32>>,
}

// EigenDACert contains all data necessary to retrieve and validate a blob
//
// This struct represents the composition of a eigenDA blob certificate, as it would exist in a rollup inbox.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct EigenDACert {
    blob_inclusion_info: BlobInclusionInfo,
    batch_header: BatchHeaderV2,
    non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub(crate) fn new(
        blob_status_reply: BlobStatusReply,
        non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    ) -> Self {
        let binding_inclusion_info =
            BlobInclusionInfo::from(blob_status_reply.blob_inclusion_info.unwrap()); // TODO: handle error

        let signed_batch = blob_status_reply.signed_batch.unwrap(); // TODO: handle error
        let binding_batch_header = BatchHeaderV2::from(signed_batch.header.unwrap()); // TODO: handle error

        let mut signed_quorum_numbers: Vec<u8> = Vec::new();
        for q in signed_batch.attestation.unwrap().quorum_numbers {
            signed_quorum_numbers.push(q.try_into().unwrap());
        }

        Self {
            blob_inclusion_info: binding_inclusion_info,
            batch_header: binding_batch_header,
            non_signer_stakes_and_signature,
            signed_quorum_numbers,
        }
    }

    /// Computes the blob_key of the blob that belongs to the EigenDACert
    pub(crate) fn compute_blob_key(&self) -> BlobKey {
        let blob_header = self
            .blob_inclusion_info
            .blob_certificate
            .blob_header
            .clone();

        let blob_commitments = blob_header.commitment;

        let blob_key_bytes = compute_blob_key_bytes(
            blob_header.version,
            blob_commitments,
            blob_header.quorum_numbers,
            blob_header.payment_header_hash
        );

        let blob_key: BlobKey = match blob_key_bytes.try_into() {
            Ok(key) => key,
            Err(_) => panic!("invalid blob key length: expected 32 bytes"),
        };
        blob_key
    }
}

// BlobKey is the unique identifier for a blob dispersal.
//
// It is computed as the Keccak256 hash of some serialization of the blob header
// where the PaymentHeader has been replaced with Hash(PaymentHeader), in order
// to be easily verifiable onchain. See the BlobKey method of BlobHeader for more
// details.
//
// It can be used to retrieve a blob from relays.
//
// Note that two blobs can have the same content but different headers,
// so they are allowed to both exist in the system.
pub(crate) type BlobKey = [u8; 32];

fn compute_blob_key_bytes(
    version: u16,
    blob_commitments: BlobCommitment,
    quorum_numbers: Vec<u8>,
    payment_hash: [u8; 32],
) -> Vec<u8> {
    unimplemented!()
}
