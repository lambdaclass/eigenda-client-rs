use ethabi::Token;
use ethereum_types::U256;

pub(crate) struct MerkleProofInput {
    pub(crate) batch_root: [u8; 32],
    pub(crate) leaf: [u8; 32],
    pub(crate) index: U256,
    pub(crate) inclusion_proof: Vec<u8>,
}

impl MerkleProofInput {
    pub(crate) fn into_tokens(&self) -> Vec<Token> {
        vec![ Token::Tuple( vec![
            Token::FixedBytes(self.batch_root.to_vec()),
            Token::FixedBytes(self.leaf.to_vec()),
            Token::Uint(self.index.clone()),
            Token::Bytes(self.inclusion_proof.clone())])
        ]
    }
}
