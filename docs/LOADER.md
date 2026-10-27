# Direct-cable key loader

The KMF delivers keys two ways:

* **OTAR** — over the air, sealed under the subscriber's K, carried by the SwMI
  (`kmfctl otar ...`, see [`connector`](../src/connector.rs)). This is the
  ETSI EN 300 392-7 standard path and is fully implemented.
* **Cable fill** — down a serial line into a radio or a key-fill device, the way
  a hardware loader (Motorola KVL, Sepura SKMS) does it. That is what this page
  and `kmfctl loader ...` cover. Use it for the initial fill, for the
  authentication key K (which is never sent OTAR), and where OTAR is not
  available.

## Architecture

```
  KMF database ──► kmfctl loader ──► KeyFill trait ──► device profile ──► serial ──► radio
   (K/SCK/GCK)      (pulls key)      (read-tei,          (KFP | Motorola)
                                      write-k/sck/gck)
```

* [`loader::KeyFill`](../src/loader.rs) is the device-agnostic operation set:
  `hello`, `read_tei`, `write_k`, `write_sck`, `write_gck`.
* A **device profile** maps those onto a concrete wire protocol:
  * **KFP** ([`loader::kfp`](../src/loader/kfp.rs)) — the KMF Key-Fill Protocol,
    an open, CRC-16/CCITT-framed request/response protocol. Any device that
    speaks KFP works today. The built-in [`RefDevice`](../src/loader.rs) is the
    canonical device-side implementation and powers `loader selftest`.
  * **Motorola KVL** ([`loader::motorola`](../src/loader/motorola.rs)) — the seam
    for Motorola's proprietary serial dialect. **Capture-driven stub** (below).

## Commands

```bash
# No hardware: prove the whole pipeline (database -> KFP -> device) round-trips.
kmfctl loader selftest

# Real hardware needs the serial feature:
cargo build --release --features serial

# Read the attached radio's equipment identity.
kmfctl loader read-tei --port /dev/ttyUSB0 --baud 19200

# Fill keys pulled straight from the KMF database:
kmfctl loader write-k   2358245 --port /dev/ttyUSB0   # subscriber K (+ its TEI)
kmfctl loader write-sck 1       --port /dev/ttyUSB0   # slot 1's active SCK
kmfctl loader write-gck 314946  --port /dev/ttyUSB0   # group's active GCK
```

On Windows the port is `COM3` etc. The loaders in this space default to 19200
baud. The `serial` feature builds without `libudev-dev` on Linux (the port is
opened by path, no enumeration).

## KFP wire format

```text
  STX(0x02) | VER(0x01) | SEQ | OP | LEN(2, BE) | PAYLOAD | CRC(2, BE)
```

CRC is CRC-16/CCITT-FALSE over `VER..=PAYLOAD`. Requests are opcodes `< 0x70`,
responses `>= 0x70`; a device answers every request with exactly one response
(`RESP_OK`, `RESP_TEI`, `RESP_HELLO`, or `RESP_ERR` with a code + message).

| Op | Name | Payload |
|----|------|---------|
| 0x01 | HELLO     | — |
| 0x02 | READ_TEI  | — |
| 0x10 | WRITE_K   | ISSI(4) · TEI_LEN(1) · TEI · KLEN(1) · K(16) |
| 0x11 | WRITE_SCK | SCKN(1) · VN(2) · KLEN(1) · SCK(10) |
| 0x12 | WRITE_GCK | GCKN(2) · VN(2) · KLEN(1) · GCK(10) |

A DIY fill dongle (e.g. an ESP32/RP2040 with a radio-side cable) only has to
implement this handful of frames to work with `kmfctl loader --device kfp`.

## Mapping the Motorola KVL dialect

Motorola's KVL-mode serial protocol for TETRA terminals is proprietary and
undocumented. We deliberately **do not ship guessed frames** — an unverified
frame to a radio in key-load mode can corrupt its key state. `--device motorola`
therefore returns a clear error until the dialect is confirmed from a capture.

To map it (on radios you own, keys you own):

1. **Capture.** Put a loader and radio into a key-load exchange with a serial
   TAP in line. On the bench you can bridge a genuine loader to a logged pty:
   ```bash
   socat -x -v /dev/ttyUSB0,raw,echo=0 PTY,link=/tmp/kvl,raw,echo=0
   ```
   and point the loader at `/tmp/kvl`, logging both directions.
2. **Isolate** one *Read TEI* exchange and one *Write SCK* exchange (SCK is the
   safest to trial — it is not the root K).
3. **Implement** `build_read_tei`, `parse_tei`, `build_write_sck` (and the K/GCK
   equivalents) in [`loader/motorola.rs`](../src/loader/motorola.rs) from the
   captured bytes, and pin each frame with a unit test against the capture.
4. **Flip `MAPPED`** to `true` and verify against the radio.

Everything above the device layer — the database, key selection, lifecycle, the
CLI — already works; the Motorola frames are the only outstanding piece.

## Security

The fill payload is key material **in the clear** — that is unavoidable; it is
the value written into the radio. Use a short trusted cable, fill in a
controlled place, and destroy any intermediate export. `KeyMaterial` buffers are
zeroised on drop, and key material is never written to the audit log.
