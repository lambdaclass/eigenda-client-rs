use crate::core::BlobHeader;

pub trait BlobRequestSigner {
    fn sign(&self, blob: BlobHeader) -> Result<Vec<u8>, String>;

    fn sign_payment_state_request() -> Result<Vec<u8>, String>;

    fn get_account_id() -> String;
}


pub struct LocalBlobRequestSigner {

}

impl LocalBlobRequestSigner {
    pub fn new() -> Self {
        Self {}
    }
}

impl BlobRequestSigner for LocalBlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String> {
        todo!()
    }

    fn sign_payment_state_request() -> Result<Vec<u8>, String> {
        todo!()
    }

    fn get_account_id() -> String {
        todo!()
    }
}
