# tetra-kmf

An open-source **TETRA Key Management Facility (KMF)** — the authority that
generates, stores, versions and manages the lifecycle of TETRA encryption key
material, and (in later phases) drives **OTAR** provisioning to a TETRA SwMI
such as [FlowStation](https://flowstation.dev).

It is the software half of what a hardware key loader (e.g. a Motorola KVL)
plus a vendor KMF do: hold the key material, manage crypto-periods and
versions, and hand sealed keys to the infrastructure for over-the-air rekeying.

> **Licence:** GPL-3.0-or-later. **Status:** Phase 1 (key management core + CLI).

## Key material (EN 300 392-7)

| Key   | Role                                             | Length |
|-------|--------------------------------------------------|--------|
| K     | Subscriber authentication key (root secret)      | 128-bit |
| SCK   | Static Cipher Key, class 2, numbered SCKN 1–32   | 80-bit |
| GCK   | Group Cipher Key, per talkgroup                  | 80-bit |
| GSKO  | Group Session Key for OTAR (group KEK)           | 96-bit |
| CCK   | Common Cipher Key, class 3, per location area    | 80-bit |

Each key is **versioned** (SCK-VN / GCK-VN …), carries a **crypto-period**, and
moves through a lifecycle: `Staged → Active → Suspended → Retired`, with
`Compromised` as a terminal state. Secret material is zeroised in memory on drop
and never written to the audit log.

## Build

tetra-kmf depends on the [`tetra-security`](https://github.com/DavidHarcs/tetra-security)
crate for the OTAR sealing crypto. Until that crate is published to crates.io it
is referenced by path, so check both out side by side:

```
~/src/tetra-security
~/src/tetra-kmf
```

```bash
cargo build --release
```

## Encryption at rest

Set a master passphrase and the store is sealed with AES-256-GCM (otherwise a
plaintext dev store is used, with a warning):

```bash
export TETRA_KMF_MASTER_KEY="your operator passphrase"
```

## Quick start (`kmfctl`)

```bash
# create a database (written 0600)
kmfctl init

# a radio and its authentication key K
kmfctl subscriber add 2358245 "Dave MM7FDM"
kmfctl subscriber gen-k 2358245

# a talkgroup with a group cipher key
kmfctl group add 314946 "Ops"
kmfctl group add-member 314946 2358245
kmfctl group gen-gck 314946
kmfctl group activate-gck 314946 1

# a static cipher key in slot SCKN 1
kmfctl sck gen 1 "fallback"
kmfctl sck activate 1 1

# OTAR group key-encryption key
kmfctl gen-gsko

# seal an SCK for a subscriber, ready for the SwMI to transmit (D-OTAR SCK PROVIDE)
kmfctl otar seal-sck 2358245 1 1

# seal AND send it to a FlowStation SwMI to transmit over the air
kmfctl otar provide-sck 2358245 1 1 --ksg 2 --swmi https://flowstation.local --insecure

kmfctl status
```

Export a subscriber's K as hex for the **initial physical fill** (sensitive):

```bash
kmfctl subscriber export-k 2358245
```

## Roadmap

- **Phase 1 (done):** domain model, key store, secure generation, lifecycle,
  audit log, CLI.
- **Phase 2a (done):** at-rest **AES-256-GCM** encryption of the store
  (passphrase-derived key).
- **Phase 2b (done):** OTAR **SCK sealing** (TA41 → KSO, TA51 for SCK) via the
  `tetra-security` crate. GCK sealing (TA81) lands when `tetra-security` exposes
  it.
- **Phase 2c (done):** a **SwMI connector** (`HttpSwmiConnector`) that POSTs a
  sealed SCK to FlowStation's `POST /api/otar/sck`, which transmits the D-OTAR
  SCK PROVIDE PDU. K never leaves the KMF (Model B). Reporting the radio's
  result back up to the KMF is the remaining loop-closer.
- **Phase 3:** web operator console; crypto-period automation; multi-site
  (links into a TETRA network core).

## Security notes

- With `TETRA_KMF_MASTER_KEY` set, the store is encrypted at rest (AES-256-GCM).
  Without it, `JsonFileStore` keeps key material in **plaintext JSON** (0600) —
  development only.
- Secret material is zeroised in memory on drop and never written to the audit
  log. Never commit `kmf-db.json` / `kmf-audit.jsonl` (see `.gitignore`).
- Air-interface encryption on the amateur bands is not permitted; use these
  tools for authentication, interoperability and testing within your rules.

## Support

If this is useful to you, you can buy me a coffee ☕ — donations via PayPal:

**[→ Donate via PayPal](https://www.paypal.me/DavidHarcus277)**

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
