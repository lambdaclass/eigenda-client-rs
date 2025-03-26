use crate::core::BlobHeader;
use ethereum_types::Address;
use secp256k1::{SecretKey, SECP256K1};

pub trait BlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String>;

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String>;

    fn get_account_id(&self) -> Result<Address, String>;
}

pub struct LocalBlobRequestSigner {
    private_key: SecretKey,
}

impl LocalBlobRequestSigner {
    pub fn new(private_key: &str) -> Result<Self, String> {
        // Strip "0x" prefix if present
        let clean_hex = private_key.strip_prefix("0x").unwrap_or(private_key);

        // Convert hex string to bytes
        let private_key_bytes =
            hex::decode(clean_hex).map_err(|e| format!("Failed to parse private key: {}", e))?;

        // Create ECDSA private key
        let private_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;

        Ok(Self { private_key })
    }
}

impl BlobRequestSigner for LocalBlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String> {
        let blob_key = blob_header.blob_key()?;

        todo!()
    }

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String> {
        todo!()
    }

    fn get_account_id(&self) -> Result<Address, String> {
        let public_key = self.private_key.public_key(&SECP256K1);
        let address = Address::from_slice(&public_key.serialize_uncompressed()[12..]);
        Ok(address)
    }
}
