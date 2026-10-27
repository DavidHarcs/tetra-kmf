// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! The Key Management Centre service: the authority over all key material.
//!
//! Every mutating call applies the change, writes an audit record, and persists
//! the database. Secret material is never written to the audit log.

use crate::audit::AuditLog;
use crate::error::{KmfError, Result};
use crate::gen::random_key;
use crate::keys::{KeyKind, KeyState, VersionedKey};
use crate::model::{Database, Group, SckSlot, Subscriber};
use crate::provision::{KeyRef, ProvisionJob, SealedKey, Sealer, SwmiConnector};
use crate::store::KeyStore;
use crate::types::{Gssi, Issi, KeyMaterial, Sckn};

pub struct Kmc<S: KeyStore> {
    store: S,
    audit: AuditLog,
    db: Database,
}

fn next_version(list: &[VersionedKey]) -> u16 {
    list.iter().map(|v| v.version).max().unwrap_or(0) + 1
}

/// Activate `version` in a key list and retire any other currently-active version.
fn activate_in(list: &mut [VersionedKey], version: u16) -> Result<()> {
    if !list.iter().any(|v| v.version == version) {
        return Err(KmfError::NotFound(format!("key version {version}")));
    }
    for v in list.iter_mut() {
        if v.version == version {
            if v.state != KeyState::Active {
                v.set_state(KeyState::Active)?;
            }
        } else if v.state == KeyState::Active {
            v.set_state(KeyState::Retired)?;
        }
    }
    Ok(())
}

impl<S: KeyStore> Kmc<S> {
    /// Load an existing database from the store.
    pub fn open(store: S, audit: AuditLog) -> Result<Self> {
        let db = store.load()?;
        Ok(Kmc { store, audit, db })
    }

    /// Create a fresh, empty database and persist it.
    pub fn init(store: S, audit: AuditLog) -> Result<Self> {
        let db = Database::new();
        store.save(&db)?;
        let kmc = Kmc { store, audit, db };
        kmc.audit.record("init", "created new key database")?;
        Ok(kmc)
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    fn persist(&self) -> Result<()> {
        self.store.save(&self.db)
    }

    // --- subscribers -------------------------------------------------------

    pub fn add_subscriber(&mut self, issi: Issi, label: impl Into<String>) -> Result<()> {
        if self.db.subscribers.contains_key(&issi) {
            return Err(KmfError::AlreadyExists(format!("subscriber {issi}")));
        }
        self.db
            .subscribers
            .insert(issi, Subscriber::new(issi, label));
        self.audit.record("subscriber.add", format!("issi={issi}"))?;
        self.persist()
    }

    /// Generate (or rotate) the authentication key K for a subscriber. K is the
    /// bootstrap key and is created directly Active. Returns the new version.
    pub fn generate_k(&mut self, issi: Issi) -> Result<u16> {
        let sub = self
            .db
            .subscribers
            .get_mut(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let version = sub.k.as_ref().map(|k| k.version + 1).unwrap_or(1);
        let mut vk = VersionedKey::new(KeyKind::K, version, random_key(KeyKind::K))?;
        vk.set_state(KeyState::Active)?;
        sub.k = Some(vk);
        self.audit
            .record("key.k.generate", format!("issi={issi} version={version}"))?;
        self.persist()?;
        Ok(version)
    }

    /// Set a subscriber's K to a specific externally-generated value (e.g. a K
    /// imported from SFPG Rec 01 so the KMF matches what a KVL/SKMS loaded into
    /// the radio). Created Active. Returns the new version.
    pub fn import_k(&mut self, issi: Issi, material: KeyMaterial) -> Result<u16> {
        let sub = self
            .db
            .subscribers
            .get_mut(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let version = sub.k.as_ref().map(|k| k.version + 1).unwrap_or(1);
        let mut vk = VersionedKey::new(KeyKind::K, version, material)?;
        vk.set_state(KeyState::Active)?;
        sub.k = Some(vk);
        self.audit
            .record("key.k.import", format!("issi={issi} version={version}"))?;
        self.persist()?;
        Ok(version)
    }

    /// Set (or clear) a subscriber's TEI for SFPG Rec 01 K/TEI pairs.
    pub fn set_tei(&mut self, issi: Issi, tei: Option<String>) -> Result<()> {
        let sub = self
            .db
            .subscribers
            .get_mut(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        sub.tei = tei;
        self.audit.record("subscriber.set_tei", format!("issi={issi}"))?;
        self.persist()
    }

    /// Export subscriber K as hex for the initial physical fill. Sensitive.
    pub fn export_k_hex(&self, issi: Issi) -> Result<String> {
        let sub = self
            .db
            .subscribers
            .get(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let k = sub
            .k
            .as_ref()
            .ok_or_else(|| KmfError::NotFound(format!("K for subscriber {issi}")))?;
        Ok(k.material.to_hex())
    }

    /// A subscriber's TEI (equipment identity), if set.
    pub fn subscriber_tei(&self, issi: Issi) -> Option<String> {
        self.db.subscribers.get(&issi).and_then(|s| s.tei.clone())
    }

    /// The active SCK in a slot as `(version, hex)`, for a cable fill. Sensitive.
    /// Errs if the slot has no Active version.
    pub fn active_sck_hex(&self, sckn: Sckn) -> Result<(u16, String)> {
        let slot = self
            .db
            .sck_slots
            .get(&sckn.get())
            .ok_or_else(|| KmfError::NotFound(format!("sck slot {sckn}")))?;
        let v = slot
            .versions
            .iter()
            .find(|v| v.state == KeyState::Active)
            .ok_or_else(|| KmfError::Policy(format!("SCK slot {sckn} has no active version")))?;
        Ok((v.version, v.material.to_hex()))
    }

    /// The active GCK for a group as `(version, hex)`, for a cable fill. Sensitive.
    /// Errs if the group has no Active GCK version.
    pub fn active_gck_hex(&self, gssi: Gssi) -> Result<(u16, String)> {
        let group = self
            .db
            .groups
            .get(&gssi)
            .ok_or_else(|| KmfError::NotFound(format!("group {gssi}")))?;
        let v = group
            .gck
            .iter()
            .find(|v| v.state == KeyState::Active)
            .ok_or_else(|| KmfError::Policy(format!("group {gssi} has no active GCK")))?;
        Ok((v.version, v.material.to_hex()))
    }

    // --- groups ------------------------------------------------------------

    pub fn add_group(&mut self, gssi: Gssi, label: impl Into<String>) -> Result<()> {
        if self.db.groups.contains_key(&gssi) {
            return Err(KmfError::AlreadyExists(format!("group {gssi}")));
        }
        self.db.groups.insert(gssi, Group::new(gssi, label));
        self.audit.record("group.add", format!("gssi={gssi}"))?;
        self.persist()
    }

    pub fn add_member(&mut self, gssi: Gssi, issi: Issi) -> Result<()> {
        if !self.db.subscribers.contains_key(&issi) {
            return Err(KmfError::NotFound(format!("subscriber {issi}")));
        }
        let group = self
            .db
            .groups
            .get_mut(&gssi)
            .ok_or_else(|| KmfError::NotFound(format!("group {gssi}")))?;
        if !group.members.contains(&issi) {
            group.members.push(issi);
        }
        self.audit
            .record("group.member.add", format!("gssi={gssi} issi={issi}"))?;
        self.persist()
    }

    pub fn generate_gck(&mut self, gssi: Gssi) -> Result<u16> {
        let group = self
            .db
            .groups
            .get_mut(&gssi)
            .ok_or_else(|| KmfError::NotFound(format!("group {gssi}")))?;
        let version = next_version(&group.gck);
        group
            .gck
            .push(VersionedKey::new(KeyKind::Gck, version, random_key(KeyKind::Gck))?);
        self.audit
            .record("key.gck.generate", format!("gssi={gssi} version={version}"))?;
        self.persist()?;
        Ok(version)
    }

    pub fn activate_gck(&mut self, gssi: Gssi, version: u16) -> Result<()> {
        let group = self
            .db
            .groups
            .get_mut(&gssi)
            .ok_or_else(|| KmfError::NotFound(format!("group {gssi}")))?;
        activate_in(&mut group.gck, version)?;
        self.audit
            .record("key.gck.activate", format!("gssi={gssi} version={version}"))?;
        self.persist()
    }

    // --- SCK slots ---------------------------------------------------------

    pub fn ensure_sck_slot(&mut self, sckn: Sckn, label: impl Into<String>) -> Result<()> {
        self.db
            .sck_slots
            .entry(sckn.get())
            .or_insert_with(|| SckSlot::new(sckn.get(), label));
        self.audit.record("sck.slot.ensure", format!("sckn={sckn}"))?;
        self.persist()
    }

    pub fn generate_sck(&mut self, sckn: Sckn) -> Result<u16> {
        let slot = self
            .db
            .sck_slots
            .entry(sckn.get())
            .or_insert_with(|| SckSlot::new(sckn.get(), String::new()));
        let version = next_version(&slot.versions);
        slot.versions
            .push(VersionedKey::new(KeyKind::Sck, version, random_key(KeyKind::Sck))?);
        self.audit
            .record("key.sck.generate", format!("sckn={sckn} version={version}"))?;
        self.persist()?;
        Ok(version)
    }

    pub fn activate_sck(&mut self, sckn: Sckn, version: u16) -> Result<()> {
        let slot = self
            .db
            .sck_slots
            .get_mut(&sckn.get())
            .ok_or_else(|| KmfError::NotFound(format!("sck slot {sckn}")))?;
        activate_in(&mut slot.versions, version)?;
        self.audit
            .record("key.sck.activate", format!("sckn={sckn} version={version}"))?;
        self.persist()
    }

    // --- GSKO --------------------------------------------------------------

    pub fn generate_gsko(&mut self) -> Result<u16> {
        let version = next_version(&self.db.gsko);
        self.db
            .gsko
            .push(VersionedKey::new(KeyKind::Gsko, version, random_key(KeyKind::Gsko))?);
        self.audit
            .record("key.gsko.generate", format!("version={version}"))?;
        self.persist()?;
        Ok(version)
    }

    // --- OTAR --------------------------------------------------------------

    /// Seal an SCK version for a target subscriber, ready for the SwMI to carry
    /// in a D-OTAR SCK PROVIDE PDU. The subscriber's K must be present and not
    /// compromised, and the SCK version must exist. The `sealer` is injected so
    /// the KMC core stays independent of the crypto implementation.
    pub fn seal_sck_for<SE: Sealer>(
        &self,
        sealer: &SE,
        issi: Issi,
        sckn: Sckn,
        version: u16,
    ) -> Result<SealedKey> {
        let sub = self
            .db
            .subscribers
            .get(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let k = sub
            .k
            .as_ref()
            .ok_or_else(|| KmfError::NotFound(format!("K for subscriber {issi}")))?;
        if k.state == KeyState::Compromised {
            return Err(KmfError::Policy(format!("K for subscriber {issi} is compromised")));
        }
        let slot = self
            .db
            .sck_slots
            .get(&sckn.get())
            .ok_or_else(|| KmfError::NotFound(format!("sck slot {sckn}")))?;
        let skv = slot
            .versions
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| KmfError::NotFound(format!("SCK {sckn} v{version}")))?;
        let job = ProvisionJob::new(issi, KeyRef::Sck { sckn, version });
        let sealed = sealer.seal(&job, &k.material, &skv.material)?;
        self.audit.record(
            "otar.sck.seal",
            format!("issi={issi} sckn={sckn} version={version}"),
        )?;
        Ok(sealed)
    }

    /// Seal an SCK for `issi` and hand it to the SwMI connector to transmit as a
    /// D-OTAR SCK PROVIDE. K never leaves the KMF. `ksg` is the 1-based TEA number
    /// (1=TEA1, 2=TEA2, 3=TEA3). Returns the SwMI's acceptance status.
    pub fn provision_sck<SE: Sealer, SW: SwmiConnector>(
        &self,
        sealer: &SE,
        connector: &SW,
        issi: Issi,
        sckn: Sckn,
        version: u16,
        ksg: u8,
    ) -> Result<String> {
        let sealed = self.seal_sck_for(sealer, issi, sckn, version)?;
        let status = connector.provide_sck(
            issi,
            sckn.air(),
            version,
            ksg.saturating_sub(1),
            &sealed.sealed,
            &sealed.rso,
        )?;
        self.audit.record(
            "otar.sck.provision",
            format!("issi={issi} sckn={sckn} version={version} ksg={ksg} status={status}"),
        )?;
        Ok(status)
    }

    /// Seal a group's GCK (number `gckn`, version `version`) for `issi` and send
    /// it to the SwMI to transmit as a D-OTAR GCK PROVIDE associated to `gssi`.
    /// Sealed in individual mode under the subscriber's K. `ksg` is 1-based.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_gck<SE: Sealer, SW: SwmiConnector>(
        &self,
        sealer: &SE,
        connector: &SW,
        issi: Issi,
        gssi: Gssi,
        version: u16,
        gckn: u16,
        ksg: u8,
    ) -> Result<String> {
        let sub = self
            .db
            .subscribers
            .get(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let k = sub
            .k
            .as_ref()
            .ok_or_else(|| KmfError::NotFound(format!("K for subscriber {issi}")))?;
        if k.state == KeyState::Compromised {
            return Err(KmfError::Policy(format!("K for subscriber {issi} is compromised")));
        }
        let group = self
            .db
            .groups
            .get(&gssi)
            .ok_or_else(|| KmfError::NotFound(format!("group {gssi}")))?;
        let gckv = group
            .gck
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| KmfError::NotFound(format!("GCK v{version} for group {gssi}")))?;
        let (sgck, rso) = sealer.seal_gck(&k.material, &gckv.material, version, gckn)?;
        let status =
            connector.provide_gck(issi, gckn, version, ksg.saturating_sub(1), gssi, &sgck, &rso)?;
        self.audit.record(
            "otar.gck.provision",
            format!("issi={issi} gssi={gssi} gckn={gckn} version={version} ksg={ksg} status={status}"),
        )?;
        Ok(status)
    }

    // --- lifecycle (compromise) -------------------------------------------

    /// Flag a subscriber's K compromised (terminal). Does not delete it, so the
    /// event is auditable and the key can never be reactivated.
    pub fn compromise_k(&mut self, issi: Issi) -> Result<()> {
        let sub = self
            .db
            .subscribers
            .get_mut(&issi)
            .ok_or_else(|| KmfError::NotFound(format!("subscriber {issi}")))?;
        let k = sub
            .k
            .as_mut()
            .ok_or_else(|| KmfError::NotFound(format!("K for subscriber {issi}")))?;
        k.set_state(KeyState::Compromised)?;
        self.audit.record("key.k.compromise", format!("issi={issi}"))?;
        self.persist()
    }
}
