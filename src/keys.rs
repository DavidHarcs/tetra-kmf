// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! TETRA key kinds, lifecycle state, crypto-periods and versioned keys.

use crate::error::{KmfError, Result};
use crate::types::KeyMaterial;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The TETRA key kinds a KMF holds (EN 300 392-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKind {
    /// Authentication key, per subscriber. 128-bit.
    K,
    /// Static Cipher Key (class 2), numbered SCKN 1..=32. 80-bit.
    Sck,
    /// Group Cipher Key, per group. 80-bit.
    Gck,
    /// Group Session Key for OTAR (KEK for group key distribution). 80-bit.
    Gsko,
    /// Common Cipher Key (class 3), per location area. 80-bit.
    Cck,
}

impl KeyKind {
    /// Required key length in bytes.
    pub fn byte_len(self) -> usize {
        match self {
            KeyKind::K => 16, // 128-bit
            KeyKind::Sck | KeyKind::Gck | KeyKind::Gsko | KeyKind::Cck => 10, // 80-bit
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyKind::K => "K",
            KeyKind::Sck => "SCK",
            KeyKind::Gck => "GCK",
            KeyKind::Gsko => "GSKO",
            KeyKind::Cck => "CCK",
        }
    }

    /// Validate that `m` is the right length for this kind.
    pub fn check_len(self, m: &KeyMaterial) -> Result<()> {
        if m.len() == self.byte_len() {
            Ok(())
        } else {
            Err(KmfError::InvalidKeyLength {
                kind: self.name(),
                expected: self.byte_len(),
                got: m.len(),
            })
        }
    }
}

/// Lifecycle state of a key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Generated and stored, not yet in use.
    Staged,
    /// In active use.
    Active,
    /// Temporarily withdrawn from use, may be re-activated.
    Suspended,
    /// Permanently withdrawn after its crypto-period.
    Retired,
    /// Known or suspected compromised — must never be used again.
    Compromised,
}

impl KeyState {
    /// States a key version may move to from `self`.
    pub fn can_transition_to(self, next: KeyState) -> bool {
        use KeyState::*;
        match (self, next) {
            // Compromised is terminal.
            (Compromised, _) => false,
            (_, Compromised) => true, // anything can be flagged compromised
            (Staged, Active) => true,
            (Active, Suspended) | (Suspended, Active) => true,
            (Active, Retired) | (Suspended, Retired) | (Staged, Retired) => true,
            _ => false,
        }
    }
}

/// Validity window (crypto-period) for a key version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPeriod {
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

impl CryptoPeriod {
    pub fn open_ended(from: DateTime<Utc>) -> Self {
        CryptoPeriod {
            valid_from: from,
            valid_until: None,
        }
    }

    pub fn is_current(&self, now: DateTime<Utc>) -> bool {
        now >= self.valid_from && self.valid_until.map(|u| now < u).unwrap_or(true)
    }
}

/// A single version of a key: the material plus its number, state and period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedKey {
    pub kind: KeyKind,
    /// Key version number (SCK-VN / GCK-VN / etc.).
    pub version: u16,
    pub material: KeyMaterial,
    pub state: KeyState,
    pub period: CryptoPeriod,
    pub created: DateTime<Utc>,
}

impl VersionedKey {
    pub fn new(kind: KeyKind, version: u16, material: KeyMaterial) -> Result<Self> {
        kind.check_len(&material)?;
        let now = Utc::now();
        Ok(VersionedKey {
            kind,
            version,
            material,
            state: KeyState::Staged,
            period: CryptoPeriod::open_ended(now),
            created: now,
        })
    }

    pub fn set_state(&mut self, next: KeyState) -> Result<()> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(KmfError::Policy(format!(
                "cannot move {} v{} from {:?} to {next:?}",
                self.kind.name(),
                self.version,
                self.state
            )))
        }
    }

    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.state == KeyState::Active && self.period.is_current(now)
    }
}
