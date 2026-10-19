// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Key-material interchange aligned to TCCA SFPG **Recommendation 01** (air
//! interface authentication key K / K·TEI pairs), for exchanging K with an
//! external loader such as Sepura SKMS or a Motorola KVL.
//!
//! The exact Rec 01 on-disk framing is in the members-only SFPG document, so
//! this uses a simple, documented CSV carrying the same fields (ISSI, TEI, K).
//! It is trivially convertible to/from the real Rec 01 file once that framing
//! is confirmed against SKMS.
//!
//! # SECURITY
//! An export contains **authentication key K in the clear** — it is the value a
//! loader writes into the radio. Treat an export file as key material: write it
//! `0600`, move it over a trusted channel, and destroy it after loading.

use crate::error::{KmfError, Result};
use crate::model::Database;
use crate::types::KeyMaterial;

/// One imported K record.
pub struct ImportedK {
    pub issi: u32,
    pub tei: Option<String>,
    pub k: KeyMaterial,
}

/// Export every subscriber that has a K as `ISSI,TEI,K_hex` CSV.
pub fn export_csv(db: &Database) -> String {
    let mut out = String::new();
    out.push_str("# tetra-kmf key export — SFPG Recommendation 01 aligned (AIE authentication key K)\n");
    out.push_str("# fields: ISSI,TEI,K_hex\n");
    out.push_str("# WARNING: contains authentication key material in the clear.\n");
    for s in db.subscribers.values() {
        if let Some(k) = &s.k {
            out.push_str(&format!(
                "{},{},{}\n",
                s.issi,
                s.tei.as_deref().unwrap_or(""),
                k.material.to_hex()
            ));
        }
    }
    out
}

/// Parse an `ISSI,TEI,K_hex` CSV (comment/blank lines ignored).
pub fn parse_csv(text: &str) -> Result<Vec<ImportedK>> {
    let mut rows = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut f = t.split(',');
        let issi = f
            .next()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or_else(|| KmfError::Policy(format!("line {}: bad ISSI", lineno + 1)))?;
        let tei = f.next().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let k_hex = f
            .next()
            .ok_or_else(|| KmfError::Policy(format!("line {}: missing K", lineno + 1)))?;
        let k = KeyMaterial::from_hex(k_hex.trim())?;
        if k.len() != 16 {
            return Err(KmfError::InvalidKeyLength { kind: "K", expected: 16, got: k.len() });
        }
        rows.push(ImportedK { issi, tei, k });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Subscriber;
    use crate::keys::{KeyKind, VersionedKey};

    #[test]
    fn export_then_parse_round_trips() {
        let mut db = Database::new();
        let mut sub = Subscriber::new(2358245, "Dave");
        sub.tei = Some("00112233445566".to_string());
        sub.k = Some(VersionedKey::new(KeyKind::K, 1, KeyMaterial::from_bytes(vec![0x11; 16])).unwrap());
        db.subscribers.insert(2358245, sub);

        let csv = export_csv(&db);
        let rows = parse_csv(&csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].issi, 2358245);
        assert_eq!(rows[0].tei.as_deref(), Some("00112233445566"));
        assert_eq!(rows[0].k.as_bytes(), &[0x11; 16]);
    }

    #[test]
    fn rejects_short_k() {
        assert!(parse_csv("1,,aabb").is_err());
    }
}
