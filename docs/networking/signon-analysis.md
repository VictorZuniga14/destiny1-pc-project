# M4.10 — SignOn Protocol Analysis & Offline Session Boundary

## Purpose

Formalize **offline** SignOn HTTPS knowledge already backed by project evidence, and provide a clean session-material boundary:

```text
SignOn Evidence → Session Material Metadata → BAP Session Boundary
```

This milestone does **not** implement real login, OAuth, credential handling, or live HTTP.

## Evidence sources

- [`signon-https.md`](signon-https.md)
- [`session-crypto-key-material.md`](session-crypto-key-material.md)
- Capture workflow reference `20260529-003132` (PS3 / d1-re)
- External reference: `kallsyms/d1-re` `collect_signon_secrets` / `derive_bap_session` (not copied)

## Observed transport

| Fact | Status |
| ---- | ------ |
| HTTPS (TLS) before BAP TCP | CONFIRMED |
| Path `/SignOn` with `platform=ps3_ppu` | CONFIRMED (PS3) |
| Exact SignOn host in this repo | UNKNOWN / omitted |
| Complete wire schema | UNKNOWN |

## Observed fields

Metadata-only fields include identifiers (`platform`, `build`), secret-material **presence** (`aes_key` length 16, `mac_key` ≥16), and optional BAP endpoint candidates.

Field names alone do not invent semantics.

## Secret material policy

- SignOn analysis is offline.
- Real SignOn is not implemented.
- No external authentication is performed.
- No credentials are stored.
- No session secrets are stored.
- Session material values are never serialized.
- Offline synthetic material is used only for tests.
- Real-client compatibility remains unverified.
- Real-server compatibility remains unverified.

Sensitive JSON keys (`token`, `session_key`, `password`, `authorization`, …) carrying values are **rejected**.

## Session material metadata

`SignOnSessionMaterial` records presence and lengths only:

- AES key length 16
- session nonce length 12
- MAC material presence/length when documented

No key/nonce/token bytes.

## SessionMaterialProvider

Abstraction separating:

- **HOW** material was obtained (HTTP/cookies/OAuth/credentials — never known to BAP)
- **HOW** BAP uses material (`SessionCryptoContext`)

## Offline provider

`OfflineSessionMaterialProvider` uses `test_crypto_material` constants:

- key `00..=0f`
- nonce `10..=1b`
- labeled `SYNTHETIC_TEST_ONLY`

## BAP boundary

```text
OfflineSessionMaterialProvider
        ↓
validated synthetic material
        ↓
SessionCryptoContext
        ↓
BAP encrypted frame
```

`RealSignOnProvider` always returns `NOT_IMPLEMENTED`.

## Unknowns

- Full SignOn request/response schema
- Exhaustive field list
- Platform ticket layouts
- Cross-platform SignOn equivalence
- Exact production host (intentionally not stored here)

## Limitations

Offline analysis ≠ real SignOn compatibility. Local/synthetic success does not prove Destiny client or server interoperability.

## Future real-provider boundary

A future legitimate provider may implement `SessionMaterialProvider` without teaching BAP about HTTP or credentials. Until then, real SignOn remains blocked.

## How to run

```bash
cd network
cargo run -- signon-verify
cargo run -- signon-report
```

Expected: `SIGNON_ANALYSIS: VERIFIED` and `secret_values_stored: 0`.
