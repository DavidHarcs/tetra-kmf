// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Core identifier and key-material types.

use crate::error::{KmfError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Individual Short Subscriber Identity (24-bit on air; held as u32).
pub type Issi = u32;

/// Group Short Subscriber Identity (24-bit on air; held as u32).
pub type Gssi = u32;

/// SCK number, 1..=32 per EN 300 392-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Sckn(u8);

impl Sckn {
    pub fn new(n: u8) -> Result<Self> {
        if (1..=32).contains(&n) {
            Ok(Sckn(n))
        } else {
            Err(KmfError::InvalidSckn(n))
        }
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

impl std::fmt::Display for Sckn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Secret key bytes. Zeroised on drop, never printed in the clear, serialised as hex.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial(Vec<u8>);

impl KeyMaterial {
    pub fn from_bytes(b: Vec<u8>) -> Self {
        KeyMaterial(b)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        hex::decode(s.trim())
            .map(KeyMaterial)
            .map_err(|_| KmfError::BadHex)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hex of the raw bytes. Handle with care — this is the secret in the clear.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyMaterial({} bytes, REDACTED)", self.0.len())
    }
}

impl Serialize for KeyMaterial {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeyMaterial {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        KeyMaterial::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
