//! Encryption for secret values and the local cache.
//!
//! XChaCha20-Poly1305 with a random 24-byte nonce per value. Stored format:
//! `nonce (24 bytes) || ciphertext + tag`. The "associated data" (aad) binds
//! each ciphertext to where it belongs (e.g. "production/STRIPE_SECRET_KEY"),
//! so a value copied into another row or environment fails to decrypt.

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// A new random key from the operating system's RNG.
    pub fn generate() -> Self {
        let key = Key::generate();
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&key);
        Self(bytes)
    }

    /// Parse the 64-character hex form used in `SECRETS_KEY`.
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim()).context("SECRETS_KEY must be hex (run `secrets-inject keygen`)")?;
        let bytes: [u8; KEY_LEN] = raw
            .try_into()
            .map_err(|_| anyhow!("SECRETS_KEY must be 64 hex characters (32 bytes)"))?;
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// A separate key for another purpose (e.g. the cache), derived from this one.
    pub fn derive(&self, context: &str) -> SecretKey {
        SecretKey(blake3::derive_key(context, &self.0))
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&Key::from(self.0));
        let nonce = XNonce::generate();
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .expect("encryption cannot fail for in-memory buffers");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN + 16 {
            bail!("ciphertext is too short");
        }
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).expect("length checked above");
        let cipher = XChaCha20Poly1305::new(&Key::from(self.0));
        cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow!("decryption failed (wrong SECRETS_KEY, or the data was changed)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretKey::generate();
        let ct = key.encrypt(b"hunter2", b"production/DB_PASSWORD");
        assert_eq!(key.decrypt(&ct, b"production/DB_PASSWORD").unwrap(), b"hunter2");
    }

    #[test]
    fn wrong_key_or_location_fails() {
        let key = SecretKey::generate();
        let ct = key.encrypt(b"hunter2", b"production/DB_PASSWORD");
        assert!(SecretKey::generate().decrypt(&ct, b"production/DB_PASSWORD").is_err());
        assert!(key.decrypt(&ct, b"staging/DB_PASSWORD").is_err());
    }

    #[test]
    fn hex_round_trip() {
        let key = SecretKey::generate();
        let again = SecretKey::from_hex(&key.to_hex()).unwrap();
        assert_eq!(key.0, again.0);
        assert!(SecretKey::from_hex("abcd").is_err());
    }
}