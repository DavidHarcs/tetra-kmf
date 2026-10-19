// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! The key database: subscribers, groups, SCK slots and the shared GSKO/CCK sets.

use crate::keys::VersionedKey;
use crate::types::{Gssi, Issi};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A radio subscriber and its authentication key K.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscriber {
    pub issi: Issi,
    pub label: String,
    /// Authentication key K (versioned). None until a key is provisioned.
    pub k: Option<VersionedKey>,
    pub enabled: bool,
    /// TETRA Equipment Identity (hardware serial), for SFPG Rec 01 K/TEI pairs.
    #[serde(default)]
    pub tei: Option<String>,
}

impl Subscriber {
    pub fn new(issi: Issi, label: impl Into<String>) -> Self {
        Subscriber {
            issi,
            label: label.into(),
            k: None,
            enabled: true,
            tei: None,
        }
    }
}

/// A talkgroup and its group cipher keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub gssi: Gssi,
    pub label: String,
    /// GCK versions for this group (newest last).
    pub gck: Vec<VersionedKey>,
    /// Member ISSIs associated with the group for key distribution.
    pub members: Vec<Issi>,
}

impl Group {
    pub fn new(gssi: Gssi, label: impl Into<String>) -> Self {
        Group {
            gssi,
            label: label.into(),
            gck: Vec::new(),
            members: Vec::new(),
        }
    }
}

/// A static-cipher-key slot (one SCKN) and its versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SckSlot {
    /// SCK number 1..=32 (stored as the raw u8).
    pub sckn: u8,
    pub label: String,
    /// SCK versions in this slot (newest last).
    pub versions: Vec<VersionedKey>,
}

impl SckSlot {
    pub fn new(sckn: u8, label: impl Into<String>) -> Self {
        SckSlot {
            sckn,
            label: label.into(),
            versions: Vec::new(),
        }
    }
}

/// The complete key database. Serialised as a whole by the store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Database {
    pub subscribers: BTreeMap<Issi, Subscriber>,
    pub groups: BTreeMap<Gssi, Group>,
    /// Keyed by SCKN (1..=32).
    pub sck_slots: BTreeMap<u8, SckSlot>,
    /// Group Session Key for OTAR (shared KEK), versioned.
    pub gsko: Vec<VersionedKey>,
    /// Common Cipher Keys keyed by location area.
    pub cck: BTreeMap<u16, Vec<VersionedKey>>,
    /// Monotonic schema marker for future migrations.
    pub schema: u32,
}

impl Database {
    pub fn new() -> Self {
        Database {
            schema: 1,
            ..Default::default()
        }
    }
}
