// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Secure key generation.
//!
//! Key material is drawn from the operating system CSPRNG (`OsRng`, backed by
//! `getrandom`) at the exact bit length for each TETRA key kind.

use crate::keys::KeyKind;
use crate::types::KeyMaterial;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate fresh random key material of the correct length for `kind`.
pub fn random_key(kind: KeyKind) -> KeyMaterial {
    let mut buf = vec![0u8; kind.byte_len()];
    OsRng.fill_bytes(&mut buf);
    KeyMaterial::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_correct_lengths() {
        assert_eq!(random_key(KeyKind::K).len(), 16);
        assert_eq!(random_key(KeyKind::Sck).len(), 10);
        assert_eq!(random_key(KeyKind::Gck).len(), 10);
        assert_eq!(random_key(KeyKind::Gsko).len(), 12);
        assert_eq!(random_key(KeyKind::Cck).len(), 10);
    }

    #[test]
    fn two_keys_differ() {
        // Astronomically unlikely to collide; guards a stuck RNG.
        assert_ne!(
            random_key(KeyKind::K).to_hex(),
            random_key(KeyKind::K).to_hex()
        );
    }
}
