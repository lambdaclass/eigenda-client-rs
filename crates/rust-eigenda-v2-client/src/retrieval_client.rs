use std::collections::HashMap;

use ark_bn254::{Fr, G1Affine};
use ethereum_types::U256;

use crate::{core::{
    eigenda_cert::{BlobCommitment, BlobKey},
    BYTES_PER_SYMBOL,
}, generated::validator::GetChunksRequest};

// TODO: Relocate structs?

/// Proof is used to open a commitment. In the case of Kzg, this is also a kzg commitment, and is different from a Commitment only semantically.
pub(crate) type Proof = G1Affine;
/// Symbol is a symbol in the field used for polynomial commitments
pub(crate) type Symbol = Fr;

/// Frame is a chunk of data with the associated multi-reveal proof
pub(crate) struct Frame {
    /// proof is the multireveal proof corresponding to the chunk
    proof: Proof,
    // coeffs contains the coefficients of the interpolating polynomial of the chunk
    coeffs: Vec<Symbol>,
}

pub(crate) type ChunkNumber = usize;

#[derive(Clone)]
pub(crate) struct EncodingParams {
    num_chunks: u64, // number of total chunks that are padded to power of 2
    chunk_len: u64,  // number of Fr symbol stored inside a chunk
}

pub(crate) struct BlobVersionParameters {
    coding_rate: u32,
    max_num_operators: u32,
    num_chunks: u32,
}

/// Trait that defines the methods for the eth_client used by the retrieval client
#[async_trait::async_trait]
pub(crate) trait RetrievalEthClient: Sync + Send + std::fmt::Debug {
    async fn get_all_versioned_blob_params(
        &self,
    ) -> Result<HashMap<u16, BlobVersionParameters>, String>;
}

/// OperatorState contains information about the current state of operators which is stored in the blockchain state
pub(crate) struct OperatorState {
    // Operators is a map from quorum ID to a map from the operators in that quorum to their StoredOperatorInfo. Membership
    // in the map implies membership in the quorum.
    operators: HashMap<u8, HashMap<usize, OperatorInfo>>,
    // Totals is a map from quorum ID to the total stake (Stake) and total count (Index) of all operators in that quorum
    totals: HashMap<u8, OperatorInfo>,
    // BlockNumber is the block number at which this state was retrieved
    block_number: usize,
}

/// Trait that defines the methods for the chain_state used by the retrieval client
#[async_trait::async_trait]
pub(crate) trait RetrievalChainStateProvider: Sync + Send + std::fmt::Debug {
    async fn get_operator_state_with_socket(
        &self,
        block_number: u64,
        quorums: Vec<u8>,
    ) -> Result<OperatorState, String>;
}

/// Trait that defines the methods for the verifier used by the retrieval client
#[async_trait::async_trait]
pub(crate) trait RetrievalVerifier: Sync + Send + std::fmt::Debug {
    async fn verify_frames(
        &self,
        chunks: &Vec<Frame>,
        indices: &Vec<ChunkNumber>,
        commitments: BlobCommitment,
        params: EncodingParams,
    ) -> Result<(), String>;

    async fn verify_commit_equivalence_batch(
        &self,
        commitments: BlobCommitment,
    ) -> Result<(), String>;

    async fn decode(
        &self,
        chunks: Vec<Frame>,
        indices: Vec<ChunkNumber>,
        params: EncodingParams,
        input_size: usize,
    ) -> Result<Vec<u8>, String>;
}

/// RetrievalClient can retrieve blobs from the DA nodes.
/// To retrieve a blob from the relay, use RelayClient instead.
pub(crate) struct RetrievalClient<
    E: RetrievalEthClient,
    C: RetrievalChainStateProvider,
    V: RetrievalVerifier,
> {
    eth_client: E,
    chain_state: C,
    verifier: V,
    num_connections: u32, // TODO: needless field?
}

impl<E: RetrievalEthClient, C: RetrievalChainStateProvider, V: RetrievalVerifier>
    RetrievalClient<E, C, V>
{
    pub(crate) fn new(eth_client: E, chain_state: C, verifier: V, num_connections: u32) -> Self {
        Self {
            eth_client,
            chain_state,
            verifier,
            num_connections,
        }
    }

    pub(crate) async fn get_blob(
        &self,
        blob_key: BlobKey,
        blob_version: u16,
        blob_commitments: BlobCommitment,
        reference_block_number: u64,
        quorum_id: u8,
    ) -> Result<Vec<u8>, String> {
        self.verifier
            .verify_commit_equivalence_batch(blob_commitments.clone())
            .await?;

        let operator_state = self
            .chain_state
            .get_operator_state_with_socket(reference_block_number, vec![quorum_id])
            .await?;
        let operators = operator_state.operators.get(&quorum_id).unwrap();

        let blob_versions = self.eth_client.get_all_versioned_blob_params().await?;
        let blob_param = blob_versions.get(&blob_version).unwrap();

        let encoding_params = get_encoding_params(blob_commitments.length, blob_param).unwrap();

        let assignments = get_assignments(&operator_state, blob_param, quorum_id);

        // Fetch chunks from all operators
        let mut replies: Vec<RetrievedChunks> = Vec::new(); // TODO: change this
        for op_id in 0..operators.len() {
            let op_info = operator_state
                .operators
                .get(&quorum_id)
                .unwrap()
                .get(&op_id)
                .unwrap()
                .clone();
            // TODO: this is done with a worker pool in go's client
            // We should work on a more parallelized implementation.
            let retrieved_chunk = self
                .get_chunks_from_operator(op_id, op_info, blob_key, quorum_id)
                .await?;
            replies.push(retrieved_chunk);
        }

        let mut chunks: Vec<Frame> = Vec::new();
        let mut indices: Vec<ChunkNumber> = Vec::new();
        for _ in 0..operators.len() {
            let reply = replies.remove(0);

            let assignment = assignments.get(&reply.operator_id).unwrap();

            let assignment_indices = assignment.get_indices();

            self.verifier
                .verify_frames(
                    &reply.chunks,
                    &assignment_indices,
                    blob_commitments.clone(),
                    encoding_params.clone(),
                )
                .await?;

            chunks.extend(reply.chunks);
            indices.extend(assignment_indices);
        }

        if chunks.is_empty() {
            return Err("failed to retrieve any chunks".to_string());
        }

        self.verifier
            .decode(
                chunks,
                indices,
                encoding_params,
                blob_commitments.length as usize * BYTES_PER_SYMBOL,
            )
            .await
    }

    pub(crate) async fn get_chunks_from_operator(
        &self,
        op_id: usize,
        op_info: OperatorInfo,
        blob_key: BlobKey,
        quorum_id: u8,
    ) -> Result<RetrievedChunks, String> {
        let request = GetChunksRequest {
            blob_key: blob_key.to_vec(),
            quorum_id: quorum_id as u32,
        };
        unimplemented!()
    }
}

pub(crate) struct RetrievedChunks {
    operator_id: usize,
    chunks: Vec<Frame>,
}

/// OperatorInfo contains information about an operator which is stored on the blockchain state,
/// corresponding to a particular quorum
#[derive(Clone)]
pub(crate) struct OperatorInfo {
    // Stake is the amount of stake held by the operator in the quorum
    stake: U256,
    // Index is the index of the operator within the quorum
    index: usize,
    // Socket is the socket address of the operator
    // Populated only when using GetOperatorStateWithSocket; otherwise it is an empty string
    socket: String, // TODO: needless type?
}

fn get_encoding_params(
    length: u32,
    blob_param: &BlobVersionParameters,
) -> Result<EncodingParams, String> {
    // TODO: implement
    Ok(EncodingParams {
        num_chunks: 0,
        chunk_len: 0,
    })
}

// Assignment contains information about the set of chunks that a specific node will receive
pub(crate) struct Assignment {
    start_index: usize,
    num_chunks: usize,
}

impl Assignment {
    /// get_indices generates the list of ChunkNumber associated with a given assignment
    pub(crate) fn get_indices(&self) -> Vec<ChunkNumber> {
        let mut indices = Vec::new();
        for ind in 0..self.num_chunks {
            indices.push(self.start_index + ind);
        }
        indices
    }
}

fn get_assignments(
    operator_state: &OperatorState,
    blob_param: &BlobVersionParameters,
    quorum_id: u8,
) -> HashMap<usize, Assignment> {
    // TODO: implement
    HashMap::new()
}
