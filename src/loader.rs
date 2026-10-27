// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Direct-cable **key loader** — writes key material from the KMF into a radio
//! or key-fill device over a serial line, the way a hardware key loader (a
//! Motorola KVL, a Sepura SKMS) does. This is the cable half of the KMF: OTAR
//! (see [`crate::connector`]) delivers keys over the air; this delivers them
//! over a wire for the initial fill or where OTAR is not available.
//!
//! # Two layers
//!
//! * A device-agnostic trait, [`KeyFill`], with the operations a loader needs:
//!   read the equipment identity (TEI), and write K / SCK / GCK.
//! * One or more *device profiles* that speak a concrete wire protocol:
//!   - [`KfpDevice`] speaks **KFP** (the KMF Key-Fill Protocol, defined in
//!     [`kfp`] below) — an open, CRC-framed request/response protocol. Any
//!     device that implements KFP (including the built-in [`RefDevice`] used by
//!     `kmfctl loader selftest`, or a DIY microcontroller fill dongle) works
//!     end to end today.
//!   - [`motorola::MotorolaKvl`] is the seam for the **Motorola KVL** serial
//!     dialect. That dialect is proprietary and undocumented, so its frames are
//!     **not** shipped guessed — the profile is a capture-driven stub. See
//!     `docs/LOADER.md` for how to capture and fill it in.
//!
//! # Security
//! The payloads here are key material **in the clear** — that is unavoidable,
//! it is what a fill writes into the radio. Use a short, trusted cable, fill in
//! a controlled place, and zeroise working buffers (the [`crate::types::KeyMaterial`]
//! type does this on drop). Nothing here is written to the audit log in clear.

use crate::error::{KmfError, Result};

pub mod kfp;
pub mod motorola;

/// The equipment identity read back from a radio (raw bytes as the device
/// returns them; typically the TEI).
pub type Tei = Vec<u8>;

/// The operations a key-fill device supports. A profile maps these onto its
/// concrete wire protocol.
pub trait KeyFill {
    /// Identify the device (free-form string, e.g. a firmware banner).
    fn hello(&mut self) -> Result<String>;

    /// Read the attached radio's equipment identity (TEI).
    fn read_tei(&mut self) -> Result<Tei>;

    /// Write a subscriber's authentication key K (16 bytes) for `issi`,
    /// optionally tagged with its `tei`.
    fn write_k(&mut self, issi: u32, tei: &[u8], k: &[u8]) -> Result<()>;

    /// Write a Static Cipher Key into slot `sckn` (1..=32), version `vn`.
    fn write_sck(&mut self, sckn: u8, vn: u16, sck: &[u8]) -> Result<()>;

    /// Write a Group Cipher Key numbered `gckn`, version `vn`.
    fn write_gck(&mut self, gckn: u16, vn: u16, gck: &[u8]) -> Result<()>;
}

/// A byte pipe that performs one request→response exchange: send a complete
/// request frame, return the device's complete response frame. Implemented by
/// the serial port, and by the in-process loopback used for the self-test.
pub trait Transport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>>;
}

// --- KFP device -------------------------------------------------------------

/// A [`KeyFill`] device that speaks KFP over any [`Transport`].
pub struct KfpDevice<T: Transport> {
    transport: T,
    seq: u8,
}

impl<T: Transport> KfpDevice<T> {
    pub fn new(transport: T) -> Self {
        KfpDevice { transport, seq: 0 }
    }

    /// Send a request opcode + payload and return the response payload, after
    /// checking the response is the expected opcode (or mapping ERR to an error).
    fn request(&mut self, op: u8, payload: &[u8], expect: u8) -> Result<Vec<u8>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let frame = kfp::encode(seq, op, payload);
        let resp = self.transport.exchange(&frame)?;
        let msg = kfp::decode(&resp)
            .map_err(|e| KmfError::Io(format!("key-fill: bad response frame: {e}")))?;
        if msg.op == kfp::RESP_ERR {
            let code = msg.payload.first().copied().unwrap_or(0);
            let text = String::from_utf8_lossy(msg.payload.get(1..).unwrap_or(&[]));
            return Err(KmfError::Policy(format!(
                "key-fill device rejected op 0x{op:02x} (code {code}): {text}"
            )));
        }
        if msg.op != expect {
            return Err(KmfError::Io(format!(
                "key-fill: expected response 0x{expect:02x}, got 0x{:02x}",
                msg.op
            )));
        }
        Ok(msg.payload)
    }
}

impl<T: Transport> KeyFill for KfpDevice<T> {
    fn hello(&mut self) -> Result<String> {
        let p = self.request(kfp::REQ_HELLO, &[], kfp::RESP_HELLO)?;
        Ok(String::from_utf8_lossy(&p).into_owned())
    }

    fn read_tei(&mut self) -> Result<Tei> {
        self.request(kfp::REQ_READ_TEI, &[], kfp::RESP_TEI)
    }

    fn write_k(&mut self, issi: u32, tei: &[u8], k: &[u8]) -> Result<()> {
        if k.len() != 16 {
            return Err(KmfError::InvalidKeyLength { kind: "K", expected: 16, got: k.len() });
        }
        let mut payload = Vec::with_capacity(4 + 1 + tei.len() + 1 + k.len());
        payload.extend_from_slice(&issi.to_be_bytes());
        payload.push(tei.len() as u8);
        payload.extend_from_slice(tei);
        payload.push(k.len() as u8);
        payload.extend_from_slice(k);
        self.request(kfp::REQ_WRITE_K, &payload, kfp::RESP_OK)?;
        Ok(())
    }

    fn write_sck(&mut self, sckn: u8, vn: u16, sck: &[u8]) -> Result<()> {
        if sck.len() != 10 {
            return Err(KmfError::InvalidKeyLength { kind: "SCK", expected: 10, got: sck.len() });
        }
        let mut payload = Vec::with_capacity(1 + 2 + 1 + sck.len());
        payload.push(sckn);
        payload.extend_from_slice(&vn.to_be_bytes());
        payload.push(sck.len() as u8);
        payload.extend_from_slice(sck);
        self.request(kfp::REQ_WRITE_SCK, &payload, kfp::RESP_OK)?;
        Ok(())
    }

    fn write_gck(&mut self, gckn: u16, vn: u16, gck: &[u8]) -> Result<()> {
        if gck.len() != 10 {
            return Err(KmfError::InvalidKeyLength { kind: "GCK", expected: 10, got: gck.len() });
        }
        let mut payload = Vec::with_capacity(2 + 2 + 1 + gck.len());
        payload.extend_from_slice(&gckn.to_be_bytes());
        payload.extend_from_slice(&vn.to_be_bytes());
        payload.push(gck.len() as u8);
        payload.extend_from_slice(gck);
        self.request(kfp::REQ_WRITE_GCK, &payload, kfp::RESP_OK)?;
        Ok(())
    }
}

// --- reference device + loopback (no hardware) ------------------------------

/// An in-memory KFP device: the canonical implementation of the protocol on the
/// *device* side. It validates requests and records what was written, so the
/// whole fill pipeline (DB → KFP → device) can be exercised with no hardware —
/// this is what `kmfctl loader selftest` drives, and what a real DIY fill dongle
/// would replicate in firmware.
#[derive(Default)]
pub struct RefDevice {
    pub tei: Vec<u8>,
    pub k: Vec<(u32, Vec<u8>)>,
    pub sck: Vec<(u8, u16, Vec<u8>)>,
    pub gck: Vec<(u16, u16, Vec<u8>)>,
}

impl RefDevice {
    pub fn new(tei: Vec<u8>) -> Self {
        RefDevice { tei, ..Default::default() }
    }

    /// Handle one decoded request, return the response (op, payload).
    fn handle(&mut self, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        match op {
            kfp::REQ_HELLO => (kfp::RESP_HELLO, b"tetra-kmf-ref-fill/1".to_vec()),
            kfp::REQ_READ_TEI => (kfp::RESP_TEI, self.tei.clone()),
            kfp::REQ_WRITE_K => match parse_write_k(payload) {
                Some((issi, _tei, k)) => {
                    self.k.push((issi, k));
                    (kfp::RESP_OK, vec![])
                }
                None => err(1, "malformed WRITE_K"),
            },
            kfp::REQ_WRITE_SCK => {
                if payload.len() >= 4 {
                    let sckn = payload[0];
                    let vn = u16::from_be_bytes([payload[1], payload[2]]);
                    let klen = payload[3] as usize;
                    if let Some(k) = payload.get(4..4 + klen) {
                        self.sck.push((sckn, vn, k.to_vec()));
                        return (kfp::RESP_OK, vec![]);
                    }
                }
                err(1, "malformed WRITE_SCK")
            }
            kfp::REQ_WRITE_GCK => {
                if payload.len() >= 5 {
                    let gckn = u16::from_be_bytes([payload[0], payload[1]]);
                    let vn = u16::from_be_bytes([payload[2], payload[3]]);
                    let klen = payload[4] as usize;
                    if let Some(k) = payload.get(5..5 + klen) {
                        self.gck.push((gckn, vn, k.to_vec()));
                        return (kfp::RESP_OK, vec![]);
                    }
                }
                err(1, "malformed WRITE_GCK")
            }
            other => err(2, &format!("unknown opcode 0x{other:02x}")),
        }
    }

    /// Decode a request frame and produce a response frame (device side).
    pub fn respond(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        let msg = kfp::decode(request)
            .map_err(|e| KmfError::Io(format!("ref device: bad request frame: {e}")))?;
        let (op, payload) = self.handle(msg.op, &msg.payload);
        Ok(kfp::encode(msg.seq, op, &payload))
    }
}

fn err(code: u8, msg: &str) -> (u8, Vec<u8>) {
    let mut p = Vec::with_capacity(1 + msg.len());
    p.push(code);
    p.extend_from_slice(msg.as_bytes());
    (kfp::RESP_ERR, p)
}

fn parse_write_k(payload: &[u8]) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    if payload.len() < 5 {
        return None;
    }
    let issi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let tlen = payload[4] as usize;
    let tei = payload.get(5..5 + tlen)?.to_vec();
    let kpos = 5 + tlen;
    let klen = *payload.get(kpos)? as usize;
    let k = payload.get(kpos + 1..kpos + 1 + klen)?.to_vec();
    Some((issi, tei, k))
}

/// A [`Transport`] that drives a [`RefDevice`] in-process (no serial port). The
/// basis of the self-test and the unit tests.
pub struct Loopback {
    pub device: RefDevice,
}

impl Loopback {
    pub fn new(device: RefDevice) -> Self {
        Loopback { device }
    }
}

impl Transport for Loopback {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        self.device.respond(request)
    }
}

// --- serial transport (feature = "serial") ----------------------------------

#[cfg(feature = "serial")]
mod serial_impl {
    use super::{kfp, KmfError, Result, Transport};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    /// KFP over a real serial port. Opens by path (no enumeration), writes the
    /// request, then reads until a whole response frame is parsed or it times out.
    pub struct SerialTransport {
        port: Box<dyn serialport::SerialPort>,
        rx: Vec<u8>,
        timeout: Duration,
    }

    impl SerialTransport {
        pub fn open(path: &str, baud: u32) -> Result<Self> {
            let port = serialport::new(path, baud)
                .timeout(Duration::from_millis(250))
                .open()
                .map_err(|e| KmfError::Io(format!("opening key-fill port {path}: {e}")))?;
            Ok(SerialTransport { port, rx: Vec::with_capacity(512), timeout: Duration::from_secs(5) })
        }
    }

    impl Transport for SerialTransport {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
            self.port
                .write_all(request)
                .map_err(|e| KmfError::Io(format!("key-fill write: {e}")))?;
            self.rx.clear();
            let deadline = Instant::now() + self.timeout;
            let mut scratch = [0u8; 256];
            loop {
                match self.port.read(&mut scratch) {
                    Ok(n) if n > 0 => self.rx.extend_from_slice(&scratch[..n]),
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => return Err(KmfError::Io(format!("key-fill read: {e}"))),
                }
                // Try to parse a complete frame from what we have so far.
                match kfp::decode(&self.rx) {
                    Ok(_) => return Ok(self.rx.clone()),
                    Err(kfp::DecodeError::Short) => {}
                    Err(e) => return Err(KmfError::Io(format!("key-fill frame: {e}"))),
                }
                if Instant::now() >= deadline {
                    return Err(KmfError::Io("key-fill: timed out waiting for device response".into()));
                }
            }
        }
    }
}

#[cfg(feature = "serial")]
pub use serial_impl::SerialTransport;

#[cfg(test)]
mod tests {
    use super::*;

    fn kfp_device() -> KfpDevice<Loopback> {
        KfpDevice::new(Loopback::new(RefDevice::new(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])))
    }

    #[test]
    fn hello_and_read_tei() {
        let mut d = kfp_device();
        assert_eq!(d.hello().unwrap(), "tetra-kmf-ref-fill/1");
        assert_eq!(d.read_tei().unwrap(), vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    #[test]
    fn write_k_sck_gck_land_on_device() {
        let dev = RefDevice::new(vec![0xaa]);
        let mut d = KfpDevice::new(Loopback::new(dev));
        d.write_k(2358245, &[0x01, 0x02], &[0x11; 16]).unwrap();
        d.write_sck(1, 3, &[0x22; 10]).unwrap();
        d.write_gck(100, 2, &[0x33; 10]).unwrap();
        // Peek the device state back out of the transport.
        let dev = &d_into_device(d).device;
        assert_eq!(dev.k, vec![(2358245u32, vec![0x11; 16])]);
        assert_eq!(dev.sck, vec![(1u8, 3u16, vec![0x22; 10])]);
        assert_eq!(dev.gck, vec![(100u16, 2u16, vec![0x33; 10])]);
    }

    // Recover the Loopback (and its RefDevice) from a KfpDevice for assertions.
    fn d_into_device(d: KfpDevice<Loopback>) -> Loopback {
        d.transport
    }

    #[test]
    fn wrong_key_length_is_rejected_before_send() {
        let mut d = kfp_device();
        assert!(d.write_k(1, &[], &[0u8; 8]).is_err());
        assert!(d.write_sck(1, 1, &[0u8; 9]).is_err());
    }

    #[test]
    fn device_rejects_bad_sckn_payload() {
        // Hand-craft a WRITE_SCK with a truncated payload → device returns ERR.
        let mut dev = RefDevice::new(vec![]);
        let bad = kfp::encode(1, kfp::REQ_WRITE_SCK, &[0x01]); // missing vn/len/key
        let resp = dev.respond(&bad).unwrap();
        let msg = kfp::decode(&resp).unwrap();
        assert_eq!(msg.op, kfp::RESP_ERR);
    }
}
