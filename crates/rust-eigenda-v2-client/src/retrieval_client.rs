struct EthClient;
struct ChainState;
struct Verifier;

pub(crate) struct RetrievalClient {
	ethc_client: EthClient,
	chain_state: ChainState,
	verifier: Verifier,
	num_connections: u32,
}

impl RetrievalClient {
	pub(crate) fn new(ethc_client: EthClient, chain_state: ChainState, verifier: Verifier, num_connections: u32) -> Self {
		Self {
			ethc_client,
			chain_state,
			verifier,
			num_connections,
		}
	}

	pub(crate) fn get_blob(&self) {
    	unimplemented!()
	}

	pub(crate) fn get_chunks_from_operator(&self) {
		unimplemented!()
	}
}
