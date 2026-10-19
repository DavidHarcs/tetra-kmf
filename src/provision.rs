// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! OTAR provisioning model.
//!
//! Phase 1 defines the job model and the [`Sealer`] / [`SwmiConnector`] traits.
//! Phase 2 implements them: sealing on top of `tetra-security`
//! (TA41 → KSO, TA51/TA52 for SCK, TA81 for GCK) and a connector that drives a
//! TETRA SwMI (e.g. FlowStation) to transmit the D-OTAR PDU and report the
//! radio's result.

use crate::error::Result;
use crate::types::{Gssi, Issi, KeyMaterial, Sckn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which stored key a provisioning job delivers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRef {
    Sck { sckn: Sckn, version: u16 },
    Gck { gssi: Gssi, version: u16 },
    Gsko { version: u16 },
}

/// Lifecycle of a single provisioning job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Sent,
    Acked,
    Failed(String),
}

/// A request to OTAR a specific key version to one radio.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionJob {
    pub id: Uuid,
    pub target: Issi,
    pub key_ref: KeyRef,
    pub created: DateTime<Utc>,
    pub status: JobStatus,
}

impl ProvisionJob {
    pub fn new(target: Issi, key_ref: KeyRef) -> Self {
        ProvisionJob {
            id: Uuid::new_v4(),
            target,
            key_ref,
            created: Utc::now(),
            status: JobStatus::Pending,
        }
    }
}

/// A key sealed for OTAR transport: opaque sealed bytes plus the random seed
/// (RSO) the SwMI needs to carry in the PDU.
#[derive(Debug, Clone)]
pub struct SealedKey {
    pub target: Issi,
    pub key_ref: KeyRef,
    pub sealed: Vec<u8>,
    pub rso: Vec<u8>,
}

/// Seals stored key material for OTAR. Implemented via `tetra-security`.
pub trait Sealer {
    /// Seal `key` (an SCK) for `job.target`, using that subscriber's K.
    fn seal(&self, job: &ProvisionJob, k: &KeyMaterial, key: &KeyMaterial) -> Result<SealedKey>;

    /// Seal a GCK (number `gckn`, version `gck_vn`) for one radio in individual
    /// mode — KSO = TA41(K, RSO) then TA81 — under that subscriber's K.
    /// Returns `(sealed GCK, RSO)`.
    fn seal_gck(
        &self,
        k: &KeyMaterial,
        gck: &KeyMaterial,
        gck_vn: u16,
        gckn: u16,
    ) -> Result<(Vec<u8>, Vec<u8>)>;
}

/// Delivers a sealed SCK to the SwMI, which transmits the D-OTAR SCK PROVIDE PDU
/// (and later reports the radio's result). All numbers are the on-air values the
/// PDU carries. Returns the SwMI's acceptance status string.
pub trait SwmiConnector {
    fn provide_sck(
        &self,
        issi: Issi,
        sckn_air: u8,
        sck_vn: u16,
        ksg_air: u8,
        ssck: &[u8],
        rso: &[u8],
    ) -> Result<String>;

    /// Deliver a sealed GCK (D-OTAR GCK PROVIDE), associated to group `gssi`.
    #[allow(clippy::too_many_arguments)]
    fn provide_gck(
        &self,
        issi: Issi,
        gckn: u16,
        gck_vn: u16,
        ksg_air: u8,
        gssi: u32,
        sgck: &[u8],
        rso: &[u8],
    ) -> Result<String>;
}
