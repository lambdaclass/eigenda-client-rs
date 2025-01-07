use ethabi::Token;
use crate::blob_info::BlobVerificationProof;

pub(crate) struct MerkleProofInput {
    pub(crate) leaf: [u8; 32],
    pub(crate) blob_verification_proof: BlobVerificationProof,
}

impl MerkleProofInput {
    pub(crate) fn to_tokens(&self) -> Vec<Token> {
        vec![Token::Tuple(vec![
            Token::FixedBytes(self.leaf.to_vec()),
            Token::Tuple(self.blob_verification_proof.to_tokens()),
        ])]
    }
}
