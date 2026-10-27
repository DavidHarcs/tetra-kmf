// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! **KFP** — the KMF Key-Fill Protocol. A small, open, CRC-framed request/
//! response protocol between the KMF (host) and a key-fill device over a serial
//! line. It is deliberately simple so a device side can be implemented in a few
//! lines of microcontroller firmware (an open equivalent of the P25 world's
//! KFDtool). The Motorola KVL dialect is a *different*, proprietary protocol —
//! see [`super::motorola`].
//!
//! ## Frame
//! ```text
//!   +------+------+------+------+---------+-----------------+--------+
//!   | STX  | VER  | SEQ  | OP   | LEN(2)  | PAYLOAD (LEN)   | CRC(2) |
//!   | 0x02 | 0x01 |      |      | BE      |                 | BE     |
//!   +------+------+------+------+---------+-----------------+--------+
//! ```
//! `CRC` is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over VER..=PAYLOAD
//! (everything between STX and the CRC). All multi-byte integers are big-endian.
//!
//! ## Opcodes
//! Requests (host → device) are below 0x70; responses (device → host) are
//! 0x70 and above. A device answers every request with exactly one response.

pub const STX: u8 = 0x02;
pub const VERSION: u8 = 0x01;

// Requests (host → device).
pub const REQ_HELLO: u8 = 0x01;
pub const REQ_READ_TEI: u8 = 0x02;
pub const REQ_WRITE_K: u8 = 0x10;
pub const REQ_WRITE_SCK: u8 = 0x11;
pub const REQ_WRITE_GCK: u8 = 0x12;

// Responses (device → host).
pub const RESP_OK: u8 = 0x70;
pub const RESP_HELLO: u8 = 0x71;
pub const RESP_TEI: u8 = 0x72;
pub const RESP_ERR: u8 = 0x7f;

/// A decoded KFP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub seq: u8,
    pub op: u8,
    pub payload: Vec<u8>,
}

/// Why a buffer could not be decoded into one complete frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes yet for a complete frame (keep reading).
    Short,
    /// First byte is not STX.
    NoStx,
    /// Protocol version byte not understood.
    BadVersion(u8),
    /// CRC check failed (got, want).
    BadCrc { got: u16, want: u16 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Short => write!(f, "incomplete frame"),
            DecodeError::NoStx => write!(f, "missing start byte"),
            DecodeError::BadVersion(v) => write!(f, "unsupported KFP version 0x{v:02x}"),
            DecodeError::BadCrc { got, want } => write!(f, "CRC mismatch (got {got:#06x}, want {want:#06x})"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode one frame.
pub fn encode(seq: u8, op: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(VERSION);
    body.push(seq);
    body.push(op);
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(payload);
    let crc = crc16_ccitt(&body);

    let mut frame = Vec::with_capacity(1 + body.len() + 2);
    frame.push(STX);
    frame.extend_from_slice(&body);
    frame.extend_from_slice(&crc.to_be_bytes());
    frame
}

/// Decode exactly one frame from the front of `buf`. Returns [`DecodeError::Short`]
/// if a whole frame is not present yet (the caller should read more bytes).
pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::Short);
    }
    if buf[0] != STX {
        return Err(DecodeError::NoStx);
    }
    // Need STX + VER + SEQ + OP + LEN(2) before we can know the length.
    if buf.len() < 6 {
        return Err(DecodeError::Short);
    }
    if buf[1] != VERSION {
        return Err(DecodeError::BadVersion(buf[1]));
    }
    let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total = 6 + len + 2; // header + payload + crc
    if buf.len() < total {
        return Err(DecodeError::Short);
    }
    let body = &buf[1..6 + len]; // VER..=PAYLOAD
    let want = crc16_ccitt(body);
    let got = u16::from_be_bytes([buf[6 + len], buf[6 + len + 1]]);
    if got != want {
        return Err(DecodeError::BadCrc { got, want });
    }
    Ok(Message {
        seq: buf[2],
        op: buf[3],
        payload: buf[6..6 + len].to_vec(),
    })
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, xorout 0).
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vector() {
        // CRC-16/CCITT-FALSE of "123456789" is 0x29B1.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29b1);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let f = encode(7, REQ_WRITE_SCK, &[1, 2, 3, 4, 5]);
        let m = decode(&f).unwrap();
        assert_eq!(m.seq, 7);
        assert_eq!(m.op, REQ_WRITE_SCK);
        assert_eq!(m.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let f = encode(1, REQ_HELLO, &[]);
        let m = decode(&f).unwrap();
        assert_eq!(m.op, REQ_HELLO);
        assert!(m.payload.is_empty());
    }

    #[test]
    fn short_buffer_is_short() {
        let f = encode(1, REQ_WRITE_K, &[9; 20]);
        assert_eq!(decode(&f[..4]), Err(DecodeError::Short));
        assert_eq!(decode(&f[..f.len() - 1]), Err(DecodeError::Short));
    }

    #[test]
    fn corrupt_crc_detected() {
        let mut f = encode(1, REQ_HELLO, &[]);
        let last = f.len() - 1;
        f[last] ^= 0xff;
        assert!(matches!(decode(&f), Err(DecodeError::BadCrc { .. })));
    }

    #[test]
    fn bad_stx_and_version() {
        let mut f = encode(1, REQ_HELLO, &[]);
        f[0] = 0x00;
        assert_eq!(decode(&f), Err(DecodeError::NoStx));
        let mut f = encode(1, REQ_HELLO, &[]);
        f[1] = 0x99;
        assert_eq!(decode(&f), Err(DecodeError::BadVersion(0x99)));
    }
}
