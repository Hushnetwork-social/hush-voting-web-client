//! Independent RustCrypto implementations of the vault v1 suite primitives.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::jcs::hex_digest;

pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
) -> Result<Vec<u8>, ()> {
    let params =
        Params::new(memory_kib, iterations, parallelism, Some(output_len)).map_err(|_| ())?;
    let algorithm = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0_u8; output_len];
    algorithm
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| ())?;
    Ok(output)
}

pub fn hkdf_sha256(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, ()> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut output = vec![0_u8; output_len];
    hkdf.expand(info, &mut output).map_err(|_| ())?;
    Ok(output)
}

pub fn aes256gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ()> {
    if nonce.len() != 12 {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ())
}

#[cfg(test)]
pub fn aes256gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ()> {
    if nonce.len() != 12 {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let mut authenticated_ciphertext = ciphertext.to_vec();
    authenticated_ciphertext.extend_from_slice(tag);
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &authenticated_ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

pub fn hkdf_vector_sha256(label: &str) -> Result<String, ()> {
    let output = hkdf_sha256(b"password-bytes", &[7_u8; 16], label.as_bytes(), 32)?;
    use sha2::{Digest, Sha256};
    Ok(hex_digest(&Sha256::digest(&output)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_labels_are_separated() {
        let credential = hkdf_vector_sha256("hush/vault/v1/credential-kek").expect("hkdf");
        let mnemonic = hkdf_vector_sha256("hush/vault/v1/mnemonic-kek").expect("hkdf");
        assert_ne!(credential, mnemonic);
        assert_eq!(credential.len(), 64);
    }

    #[test]
    fn aes_gcm_round_trip_with_aad() {
        let key = [3_u8; 32];
        let nonce = [5_u8; 12];
        let plaintext = b"ordinary record payload";
        let aad = b"aad-bytes";
        let encrypted = aes256gcm_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
        let decrypted = aes256gcm_decrypt(&key, &nonce, ciphertext, tag, aad).expect("decrypt");
        assert_eq!(decrypted, plaintext);
        let mut invalid_tag = tag.to_vec();
        invalid_tag[0] ^= 0xff;
        assert!(aes256gcm_decrypt(&key, &nonce, ciphertext, &invalid_tag, aad).is_err());
    }

    #[test]
    fn argon2id_is_deterministic() {
        let first = argon2id(b"password-bytes", &[7_u8; 16], 19_456, 2, 1, 32).expect("argon2id");
        let second = argon2id(b"password-bytes", &[7_u8; 16], 19_456, 2, 1, 32).expect("argon2id");
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
    }
}
