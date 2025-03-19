use ethabi::{ParamType, Token};
use ethereum_types::U256;
use tiny_keccak::{Keccak, Hasher};

use crate::generated::{
    common::v2::{BatchHeader, PaymentHeader},
    disperser::v2::{BlobInclusionInfo, BlobStatusReply},
};

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

/// Computes a blob key from blob information
pub fn compute_blob_key(
    blob_version: u32,
    blob_commitments: Vec<u8>,
    quorum_numbers: Vec<u32>,
    payment_header: PaymentHeader,
) -> Result<[u8; 32], ethabi::Error> {
    todo!()
}

pub(crate) struct BN254G1Point {
    x: num_bigint::BigInt,
    y: num_bigint::BigInt,
}

// TODO: is this correct?
// go bindgen:
// type BN254G2Point struct {
//     X [2]*big.Int
//     Y [2]*big.Int
// }
pub(crate) struct BN254G2Point {
    x: num_bigint::BigInt,
    y: num_bigint::BigInt,
}

pub(crate) struct NonSignerStakesAndSignature {
    non_signer_quorum_bitmap_indices: Vec<u32>,
    non_signer_pubkeys: Vec<BN254G1Point>,
    quorum_apks: Vec<BN254G1Point>,
    apk_g2: BN254G2Point,
    sigma: BN254G1Point,
    quorum_apk_indices: Vec<u32>,
    total_stake_indices: Vec<u32>,
    non_signer_stake_indices: Vec<Vec<u32>>,
}

// EigenDACert contains all data necessary to retrieve and validate a blob
//
// This struct represents the composition of a eigenDA blob certificate, as it would exist in a rollup inbox.
pub(crate) struct EigenDACert {
    blob_inclusion_info: BlobInclusionInfo,
    batch_header: BatchHeader,
    non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    signed_quorum_numbers: Vec<u8>,
}

impl EigenDACert {
    /// creates a new EigenDACert from a BlobStatusReply, and NonSignerStakesAndSignature
    pub(crate) fn new(
        blob_status_reply: BlobStatusReply,
        non_signer_stakes_and_signature: NonSignerStakesAndSignature,
    ) -> Self {
        let binding_inclusion_info = blob_status_reply.blob_inclusion_info.unwrap(); // TODO: handle error
        let signed_batch = blob_status_reply.signed_batch.unwrap();

        let binding_batch_header = signed_batch.header.unwrap();
        let quorum_numbers = signed_batch.attestation.unwrap().quorum_numbers;
        let quorum_numbers: Vec<u8> = quorum_numbers.iter().map(|q| *q as u8).collect();

        EigenDACert {
            blob_inclusion_info: binding_inclusion_info,
            batch_header: binding_batch_header,
            non_signer_stakes_and_signature,
            signed_quorum_numbers: quorum_numbers,
        }
    }

    /// Computes the blob_key of the blob that belongs to the EigenDACert
    pub(crate) fn compute_blob_key(&self) -> BlobKey {
        let blob_header = self
            .blob_inclusion_info
            .blob_certificate
            .clone()
            .unwrap()
            .blob_header
            .unwrap();
        let blob_commitments = blob_header.commitment.unwrap().commitment;

        let blob_key_bytes = compute_blob_key(
            blob_header.version, blob_commitments, blob_header.quorum_numbers, blob_header.payment_header.unwrap()
        ).unwrap();

        let blob_key: BlobKey = match blob_key_bytes.try_into() {
            Ok(key) => key,
            Err(_) => panic!("invalid blob key length: expected 32 bytes"),
        };
        blob_key
    }
}
