use ethereum_types::Address;
use secp256k1::{Message, Secp256k1, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use super::eigenda_cert::BlobHeader;

pub trait BlobRequestSigner {
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String>;

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String>;

    fn account_id(&self) -> Result<Address, String>;
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
    // TODO: change error type.
    fn sign(&self, blob_header: BlobHeader) -> Result<Vec<u8>, String> {
        let blob_key = blob_header.blob_key().map_err(|_| "Error")?;
        let secp = Secp256k1::new();
        let message = Message::from_slice(&blob_key.to_bytes()).map_err(|_| "Error")?;
        let sig = secp.sign_ecdsa(&message, &self.private_key);

        Ok(sig.serialize_der().to_vec())
    }

    fn sign_payment_state_request(&self) -> Result<Vec<u8>, String> {
        let account_id = self.account_id()?;
        println!("account_id: {:?}", account_id);

        //todo: real timestamp
        let fixedTimestamp : u64 = 1609459200000000000;

        let mut keccak_hash = Keccak::v256();
        keccak_hash.update(&(account_id.as_bytes().len() as u32).to_be_bytes());
        keccak_hash.update(account_id.as_bytes());
        keccak_hash.update(&fixedTimestamp.to_be_bytes());
        let mut account_id_hash: [u8; 32] = [0u8; 32];
        keccak_hash.finalize(&mut account_id_hash);

        println!("account_id_hash: {:?}", account_id_hash);

        // Hash the account ID bytes with SHA-256
        let hash = Sha256::digest(account_id_hash);

        println!("sha hash: {:?}", hash);

        // Create a secp256k1 message from the hash
        let message = secp256k1::Message::from_slice(hash.as_slice())
            .map_err(|e| format!("Failed to create message from hash: {}", e))?;

        // Sign the message using the private key
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &self.private_key);

        // Combine signature with recovery ID
        let mut sig_bytes = Vec::with_capacity(65);
        let (recovery_id, signature) = signature.serialize_compact();
        sig_bytes.extend_from_slice(&signature);
        sig_bytes.push(recovery_id.to_i32() as u8);

        Ok(sig_bytes)
    }

    fn account_id(&self) -> Result<Address, String> {
        let public_key = self.private_key.public_key(&SECP256K1);
        let public_key_uncompressed = public_key.serialize_uncompressed();
        let public_key_bytes = &public_key_uncompressed[1..];
        let mut keccak = Keccak::v256();
        keccak.update(&public_key_bytes);
        let mut public_key_hash: [u8; 32] = [0u8; 32];
        keccak.finalize(&mut public_key_hash);
        let address = Address::from_slice(&public_key_hash[12..]);
        Ok(address)
    }
}
