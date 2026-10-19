// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! OTAR sealing, implemented on top of the `tetra-security` crate.
//!
//! For a Static Cipher Key the flow is (EN 300 392-7 §4.5, A.8):
//! 1. draw a random seed **RSO** (80-bit);
//! 2. **KSO = TA41(K, RSO)** — a session key-encryption key from the
//!    subscriber's authentication key K;
//! 3. **SSCK = TA51(SCK, SCK-VN, KSO, SCKN)** — the sealed SCK the SwMI carries
//!    in the D-OTAR SCK PROVIDE PDU alongside RSO.
//!
//! GCK sealing (TA81) is not yet exposed by `tetra-security`, so [`TetraSealer`]
//! returns a clear error for GCK/GSKO until that lands.

use crate::error::{KmfError, Result};
use crate::provision::{KeyRef, ProvisionJob, SealedKey, Sealer};
use crate::types::KeyMaterial;
use rand::rngs::OsRng;
use rand::RngCore;
use tetra_security::taa1::otar::ta51;
use tetra_security::taa1::ta41;

/// Seals keys for OTAR using TETRA's TAA1 algorithms.
pub struct TetraSealer;

fn as_array<const N: usize>(m: &KeyMaterial, kind: &'static str) -> Result<[u8; N]> {
    m.as_bytes()
        .try_into()
        .map_err(|_| KmfError::InvalidKeyLength {
            kind,
            expected: N,
            got: m.len(),
        })
}

impl Sealer for TetraSealer {
    fn seal(&self, job: &ProvisionJob, k: &KeyMaterial, key: &KeyMaterial) -> Result<SealedKey> {
        let k16: [u8; 16] = as_array(k, "K")?;
        match &job.key_ref {
            KeyRef::Sck { sckn, version } => {
                let sck10: [u8; 10] = as_array(key, "SCK")?;
                // RSO: 80-bit random seed, carried in the PDU with the sealed key.
                let mut rso = [0u8; 10];
                OsRng.fill_bytes(&mut rso);
                let kso = ta41(&k16, &rso);
                let ssck = ta51(&sck10, *version, &kso, sckn.get());
                Ok(SealedKey {
                    target: job.target,
                    key_ref: job.key_ref.clone(),
                    sealed: ssck.to_vec(),
                    rso: rso.to_vec(),
                })
            }
            KeyRef::Gck { .. } => Err(KmfError::Policy(
                "GCK sealing (TA81) is not yet available in tetra-security".into(),
            )),
            KeyRef::Gsko { .. } => Err(KmfError::Policy(
                "GSKO sealing is not yet implemented".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyKind;
    use crate::provision::ProvisionJob;
    use crate::types::Sckn;

    #[test]
    fn seals_sck_and_tetra_security_unseals_it() {
        // Seal an SCK with a known K, then confirm tetra-security's TA52 recovers
        // the original SCK and SCKN from the sealed blob — a full round trip.
        let k = KeyMaterial::from_bytes(vec![0x11; KeyKind::K.byte_len()]);
        let sck = KeyMaterial::from_bytes(vec![0x22; KeyKind::Sck.byte_len()]);
        let sckn = Sckn::new(7).unwrap();
        let version = 3u16;

        let job = ProvisionJob::new(2358245, KeyRef::Sck { sckn, version });
        let sealed = TetraSealer.seal(&job, &k, &sck).unwrap();
        assert_eq!(sealed.rso.len(), 10);

        let k16: [u8; 16] = k.as_bytes().try_into().unwrap();
        let rso10: [u8; 10] = sealed.rso.as_slice().try_into().unwrap();
        let ssck15: [u8; tetra_security::taa1::otar::SSCK_LEN] =
            sealed.sealed.as_slice().try_into().unwrap();

        let kso = tetra_security::taa1::ta41(&k16, &rso10);
        let (recovered_sck, recovered_sckn) =
            tetra_security::taa1::otar::ta52(&ssck15, &kso, version).unwrap();
        assert_eq!(&recovered_sck[..], sck.as_bytes());
        assert_eq!(recovered_sckn, 7);
    }

    #[test]
    fn gck_sealing_errors_for_now() {
        let k = KeyMaterial::from_bytes(vec![0u8; 16]);
        let key = KeyMaterial::from_bytes(vec![0u8; 10]);
        let job = ProvisionJob::new(1, KeyRef::Gck { gssi: 100, version: 1 });
        assert!(TetraSealer.seal(&job, &k, &key).is_err());
    }
}
