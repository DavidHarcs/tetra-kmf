// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! At-rest encryption for the key store.
//!
//! The database is sealed with **AES-256-GCM**. The 256-bit content key is
//! derived from the operator master passphrase with **PBKDF2-HMAC-SHA256** over
//! a per-file random salt. Each save uses a fresh random salt and nonce.
//!
//! On-disk frame: `b"TKMF"` (4) ‖ version (1) ‖ salt (16) ‖ nonce (12) ‖
//! ciphertext‖tag.

use crate::error::{KmfError, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"TKMF";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const PBKDF2_ITERS: u32 = 600_000;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;

fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERS).expect("iteration count is non-zero"),
        salt,
        passphrase,
        &mut key,
    );
    key
}

fn rng_fill(buf: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| KmfError::Policy("system RNG failed".into()))
}

/// Encrypt `plaintext` under `passphrase`, returning the framed ciphertext.
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(KmfError::Policy("master passphrase is empty".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    rng_fill(&mut salt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng_fill(&mut nonce_bytes)?;

    let mut key_bytes = derive_key(passphrase.as_bytes(), &salt);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| KmfError::Policy("bad AEAD key".into()))?;
    key_bytes.zeroize();
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| KmfError::Policy("bad nonce".into()))?;

    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| KmfError::Policy("seal failed".into()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + buf.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt a framed ciphertext produced by [`seal`].
pub fn open(framed: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if framed.len() < HEADER_LEN + AES_256_GCM.tag_len() {
        return Err(KmfError::Policy("ciphertext too short".into()));
    }
    if &framed[0..4] != MAGIC {
        return Err(KmfError::Policy("not a tetra-kmf encrypted store".into()));
    }
    if framed[4] != VERSION {
        return Err(KmfError::Policy(format!("unsupported store version {}", framed[4])));
    }
    let salt = &framed[5..5 + SALT_LEN];
    let nonce_bytes = &framed[5 + SALT_LEN..HEADER_LEN];
    let ciphertext = &framed[HEADER_LEN..];

    let mut key_bytes = derive_key(passphrase.as_bytes(), salt);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| KmfError::Policy("bad AEAD key".into()))?;
    key_bytes.zeroize();
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| KmfError::Policy("bad nonce".into()))?;

    let mut buf = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| KmfError::Policy("decryption failed (wrong passphrase or corrupt store)".into()))?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pt = br#"{"schema":1}"#;
        let ct = seal(pt, "correct horse").unwrap();
        assert_ne!(&ct[..], &pt[..]);
        assert_eq!(open(&ct, "correct horse").unwrap(), pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ct = seal(b"secret", "right").unwrap();
        assert!(open(&ct, "wrong").is_err());
    }

    #[test]
    fn tamper_fails() {
        let mut ct = seal(b"secret", "pw").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(open(&ct, "pw").is_err());
    }

    #[test]
    fn distinct_salts_per_seal() {
        // Same plaintext + passphrase must not produce identical ciphertext.
        let a = seal(b"x", "pw").unwrap();
        let b = seal(b"x", "pw").unwrap();
        assert_ne!(a, b);
    }
}
