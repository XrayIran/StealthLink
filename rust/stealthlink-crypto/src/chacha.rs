use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

pub fn xchacha_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".to_string());
    }
    if nonce.len() != 24 {
        return Err("nonce must be 24 bytes".to_string());
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("encrypt failed: {e}"))
}

pub fn xchacha_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".to_string());
    }
    if nonce.len() != 24 {
        return Err("nonce must be 24 bytes".to_string());
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map_err(|e| format!("decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::{xchacha_decrypt, xchacha_encrypt};

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let msg = b"stealthlink";
        let aad = b"uqsp";

        let ct = xchacha_encrypt(&key, &nonce, msg, aad).expect("encrypt");
        assert_ne!(ct, msg);

        let pt = xchacha_decrypt(&key, &nonce, &ct, aad).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn rejects_invalid_key_size() {
        let err = xchacha_encrypt(&[1u8; 31], &[2u8; 24], b"x", &[]).expect_err("invalid key");
        assert!(err.contains("32 bytes"));
    }
}
