//! Thin AES-256-GCM helpers for encrypting sensitive columns at rest.
//!
//! Ciphertexts are stored as `base64(nonce || tag || ciphertext)` so they can
//! be kept in TEXT columns. The key must be exactly 32 bytes.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use base64::Engine;

use super::DbError;

const NONCE_LEN: usize = 12;

fn cipher(key: &[u8]) -> Result<Aes256Gcm, DbError> {
    if key.len() != 32 {
        return Err(DbError::Sqlx(sqlx::Error::Configuration(Box::from(
            "encryption key must be 32 bytes",
        ))));
    }
    Aes256Gcm::new_from_slice(key).map_err(|e| {
        DbError::Sqlx(sqlx::Error::Configuration(Box::from(format!(
            "invalid encryption key: {e}"
        ))))
    })
}

/// Encrypt `plaintext` with `key` and return a base64-encoded nonce-ciphertext.
pub fn encrypt(plaintext: &str, key: &[u8]) -> Result<String, DbError> {
    let cipher = cipher(key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
    let mut buffer = nonce.to_vec();
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| {
        DbError::Sqlx(sqlx::Error::Configuration(Box::from(format!(
            "encrypt: {e}"
        ))))
    })?;
    buffer.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(&buffer))
}

/// Decrypt a base64-encoded nonce-ciphertext produced by `encrypt`.
pub fn decrypt(ciphertext_b64: &str, key: &[u8]) -> Result<String, DbError> {
    let cipher = cipher(key)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| {
            DbError::Sqlx(sqlx::Error::Configuration(Box::from(format!(
                "base64: {e}"
            ))))
        })?;
    if bytes.len() < NONCE_LEN {
        return Err(DbError::Sqlx(sqlx::Error::Configuration(Box::from(
            "ciphertext too short",
        ))));
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        DbError::Sqlx(sqlx::Error::Configuration(Box::from(format!(
            "decrypt: {e}"
        ))))
    })?;
    String::from_utf8(plaintext).map_err(|e| {
        DbError::Sqlx(sqlx::Error::Configuration(Box::from(format!(
            "decrypt utf8: {e}"
        ))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encryption() {
        let key = [0u8; 32];
        let encrypted = encrypt("super secret", &key).unwrap();
        assert_ne!(encrypted, "super secret");
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "super secret");
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = [0u8; 32];
        let encrypted = encrypt("super secret", &key).unwrap();
        let wrong_key = [1u8; 32];
        assert!(decrypt(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn short_key_rejected() {
        assert!(encrypt("x", &[0u8; 16]).is_err());
    }
}
