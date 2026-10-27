// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Motorola **KVL** serial-dialect profile — the seam for filling a Motorola
//! TETRA terminal (MTP850, MTM800 …) over its programming/key-load cable, the
//! way the hardware KVL (and third-party loaders like the "CDV" tool) do.
//!
//! # Why this is a stub
//! Unlike KFP ([`super::kfp`]) and unlike OTAR (which is ETSI EN 300 392-7, a
//! public standard already implemented in [`crate::connector`]), the Motorola
//! KVL-mode **serial wire protocol is proprietary and undocumented**. We do not
//! ship guessed opcodes: sending an unverified frame to a radio in key-load mode
//! could corrupt its key state. So the write paths return a clear error until
//! the dialect is confirmed from a capture.
//!
//! # Filling it in (capture workflow)
//! 1. Put a radio you own into key-load mode with a genuine loader and a serial
//!    cable, with a port sniffer in line (e.g. a USB-serial TAP, or
//!    `interceptty`/`socat` bridging the loader to a logged pty on the bench).
//! 2. Capture a *Read TEI* exchange and one *Write SCK* exchange.
//! 3. Fill in [`build_read_tei`], [`parse_tei`], [`build_write_sck`] (and the K
//!    / GCK equivalents) with the framing you see, then flip [`MAPPED`] to true.
//! 4. The unit tests should pin each frame against the captured bytes.
//!
//! See `docs/LOADER.md` for the full procedure. Everything above this layer —
//! the KMF database, key selection, the CLI — already works; this is the only
//! device-specific piece outstanding.

use crate::error::{KmfError, Result};
use crate::loader::{KeyFill, Tei, Transport};

/// Flip to `true` once the frame builders below are backed by a real capture
/// and the round-trip tests pass against a radio.
pub const MAPPED: bool = false;

/// A Motorola KVL-dialect key-fill device over a [`Transport`] (serial).
pub struct MotorolaKvl<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> MotorolaKvl<T> {
    pub fn new(transport: T) -> Self {
        MotorolaKvl { transport }
    }
}

fn not_mapped(op: &str) -> KmfError {
    KmfError::Policy(format!(
        "Motorola KVL serial dialect for {op} is not mapped yet — it is proprietary and must be \
         confirmed from a capture before we send frames to a radio. See docs/LOADER.md. \
         Use `--device kfp` with a KFP fill device, or OTAR (`kmfctl otar ...`), meanwhile."
    ))
}

// --- frame builders (to be backed by a capture; see module docs) ------------

/// Build the bytes that request the radio's TEI. **Unverified** — returns the
/// captured request once known.
pub fn build_read_tei() -> Result<Vec<u8>> {
    Err(not_mapped("read-tei"))
}

/// Parse a TEI out of a Motorola response frame. **Unverified**.
pub fn parse_tei(_resp: &[u8]) -> Result<Tei> {
    Err(not_mapped("read-tei"))
}

/// Build the bytes that write an SCK. **Unverified**.
pub fn build_write_sck(_sckn: u8, _vn: u16, _sck: &[u8]) -> Result<Vec<u8>> {
    Err(not_mapped("write-sck"))
}

impl<T: Transport> KeyFill for MotorolaKvl<T> {
    fn hello(&mut self) -> Result<String> {
        // No harm in reporting identity even while writes are gated.
        Err(not_mapped("hello"))
    }

    fn read_tei(&mut self) -> Result<Tei> {
        Err(not_mapped("read-tei"))
    }

    fn write_k(&mut self, _issi: u32, _tei: &[u8], _k: &[u8]) -> Result<()> {
        Err(not_mapped("write-k"))
    }

    fn write_sck(&mut self, _sckn: u8, _vn: u16, _sck: &[u8]) -> Result<()> {
        Err(not_mapped("write-sck"))
    }

    fn write_gck(&mut self, _gckn: u16, _vn: u16, _gck: &[u8]) -> Result<()> {
        Err(not_mapped("write-gck"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_are_gated_until_mapped() {
        // Guard: if someone sets MAPPED without wiring real frames, this fails.
        if !MAPPED {
            assert!(build_read_tei().is_err());
            assert!(build_write_sck(1, 1, &[0u8; 10]).is_err());
        }
    }
}
