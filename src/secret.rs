#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SECRET_ID_BYTES: usize = 16;
const DELETE_TOKEN_BYTES: usize = 32;
pub const ALLOWED_TTL_SECONDS: [u64; 4] = [15 * 60, 60 * 60, 24 * 60 * 60, 7 * 24 * 60 * 60];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreateSecretRequest {
    pub ciphertext: String,
    pub nonce: String,
    pub expires_in_seconds: u64,
    pub turnstile_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateSecretResponse {
    pub id: String,
    pub delete_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadSecretResponse {
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeleteSecretRequest {
    pub delete_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteSecretResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSecretReference {
    pub secret_id: String,
    pub delete_token: String,
    pub delete_token_hash: String,
}

pub fn generate_secret_reference() -> GeneratedSecretReference {
    let secret_id = generate_random_token::<SECRET_ID_BYTES>();
    let delete_token = generate_random_token::<DELETE_TOKEN_BYTES>();
    let delete_token_hash = hash_delete_token(&delete_token);

    GeneratedSecretReference {
        secret_id,
        delete_token,
        delete_token_hash,
    }
}

pub fn hash_delete_token(delete_token: &str) -> String {
    let digest = Sha256::digest(delete_token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn is_allowed_ttl(ttl_seconds: u64) -> bool {
    ALLOWED_TTL_SECONDS.contains(&ttl_seconds)
}

fn generate_random_token<const N: usize>() -> String {
    let bytes: [u8; N] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{
        ALLOWED_TTL_SECONDS, DELETE_TOKEN_BYTES, GeneratedSecretReference, SECRET_ID_BYTES,
        generate_secret_reference, hash_delete_token, is_allowed_ttl,
    };

    #[test]
    fn generated_secret_reference_has_expected_shapes() {
        let generated = generate_secret_reference();

        assert_eq!(decode_len(&generated.secret_id), SECRET_ID_BYTES);
        assert_eq!(decode_len(&generated.delete_token), DELETE_TOKEN_BYTES);
        assert_eq!(
            generated.delete_token_hash,
            hash_delete_token(&generated.delete_token)
        );
    }

    #[test]
    fn delete_token_hash_is_deterministic_and_not_plaintext() {
        let token = "delete-token-value";

        let first = hash_delete_token(token);
        let second = hash_delete_token(token);

        assert_eq!(first, second);
        assert_ne!(first, token);
    }

    #[test]
    fn generated_secret_references_are_distinct() {
        let first: GeneratedSecretReference = generate_secret_reference();
        let second: GeneratedSecretReference = generate_secret_reference();

        assert_ne!(first.secret_id, second.secret_id);
        assert_ne!(first.delete_token, second.delete_token);
        assert_ne!(first.delete_token_hash, second.delete_token_hash);
    }

    #[test]
    fn ttl_allowlist_matches_supported_values() {
        for ttl in ALLOWED_TTL_SECONDS {
            assert!(is_allowed_ttl(ttl));
        }

        assert!(!is_allowed_ttl(42));
        assert!(!is_allowed_ttl(30 * 24 * 60 * 60));
    }

    fn decode_len(value: &str) -> usize {
        URL_SAFE_NO_PAD
            .decode(value)
            .expect("generated token should be valid base64url")
            .len()
    }
}
