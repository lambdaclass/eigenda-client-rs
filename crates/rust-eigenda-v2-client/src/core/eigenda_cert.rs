struct BN254G1Point {
    x: num_bigint::BigInt,
    y: num_bigint::BigInt,
}

// TODO: is this correct?
// go bindgen:
//  type BN254G2Point struct {
// 	    X [2]*big.Int
// 	    Y [2]*big.Int
//  }
struct BN254G2Point {
    x: num_bigint::BigInt,
    y: num_bigint::BigInt,
}

struct BlobCommitment {
    commitment: BN254G1Point,
    length_commitment: BN254G2Point,
    length_proof: BN254G2Point,
    length: u32,
}

struct BlobHeaderV2 {
    version: u16,
    quorum_numbers: Vec<u8>,
    commitment: BlobCommitment,
    payment_header_hash: [u8; 32], // TODO: replace for Vec
}

struct BlobCertificate {
    blob_header: BlobHeaderV2,
    signature: Vec<u8>,
    relay_keys: Vec<u32>,
}

struct BlobInclusionInfo {
    blob_certificate: BlobCertificate,
    blob_index: u32,
    inclusion_proof: Vec<u8>,
}

struct BatchHeader {
    blob_headers_root: [u8; 32],
    quorum_numbers: Vec<u8>,
    signed_stake_for_quorums: Vec<u8>,
    reference_block_number: u32,
}

struct NonSignerStakesAndSignature {
    non_signer_quorum_bitmap_indices: Vec<u32>,
    non_signer_pubkeys: Vec<BN254G1Point>,
    quorum_apks: Vec<BN254G1Point>,
    apk_g2: BN254G2Point,
    sigma: BN254G1Point,
    quorum_apk_indices: Vec<u32>,
    total_stake_indices: Vec<u32>,
    non_signer_stake_indices: Vec<Vec<u32>>,
}

struct BlobStatusReply {}

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
        todo!()
        // EigenDACert {
        //     signed_quorum_numbers: Vec::new(),
        // }
    }

    /// Computes the BlobKey of the blob that belongs to the EigenDACert
    pub(crate) fn compute_blob_key(&self) {}
}
