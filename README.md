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
| GSKO  | Group Session Key for OTAR (group KEK)           | 80-bit |
| CCK   | Common Cipher Key, class 3, per location area    | 80-bit |

Each key is **versioned** (SCK-VN / GCK-VN …), carries a **crypto-period**, and
moves through a lifecycle: `Staged → Active → Suspended → Retired`, with
`Compromised` as a terminal state. Secret material is zeroised in memory on drop
and never written to the audit log.

## Build

```bash
cargo build --release
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

kmfctl status
```

Export a subscriber's K as hex for the **initial physical fill** (sensitive):

```bash
kmfctl subscriber export-k 2358245
```

## Roadmap

- **Phase 1 (done):** domain model, key store, secure generation, lifecycle,
  audit log, CLI.
- **Phase 2:** at-rest AEAD encryption of the store; OTAR **sealing**
  (TA41 → KSO, TA51/TA52 for SCK, TA81 for GCK) via `tetra-security`; a **SwMI
  connector** that drives FlowStation to transmit D-OTAR and report results.
- **Phase 3:** web operator console; crypto-period automation; multi-site
  (links into a TETRA network core).

## Security notes

- Phase 1's `JsonFileStore` keeps key material in **plaintext JSON** (0600). It
  is a developer backend — at-rest encryption lands in Phase 2. Do not use it
  for production key material yet.
- Never commit `kmf-db.json` / `kmf-audit.jsonl` (see `.gitignore`).

## Support

If this is useful to you, you can buy me a coffee ☕ — donations via PayPal:

**[→ Donate via PayPal](https://www.paypal.me/DavidHarcus277)**

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
