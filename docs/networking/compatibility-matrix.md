# M4.9 — Protocol Compatibility Test Matrix

## Purpose

M4.9 converts current protocol knowledge into a **machine-readable, verifiable compatibility matrix**.

It answers objectively:

1. What is confirmed by evidence.
2. What is implemented locally.
3. What is only observed.
4. What has known structure but unknown semantics.
5. What remains blocked.
6. Which scenarios can be verified offline.
7. Which scenarios must **not** be declared compatible yet.

## Status dimensions

Statuses are **not** collapsed into one enum. Each entry carries separate dimensions:

| Dimension | Values |
| --------- | ------ |
| Evidence | `CONFIRMED`, `OBSERVED`, `STRUCTURAL`, `HYPOTHESIS`, `UNKNOWN`, `BLOCKED` |
| Implementation | `IMPLEMENTED`, `PARTIAL`, `NOT_IMPLEMENTED`, `BLOCKED` |
| Verification | `VERIFIED`, `NOT_VERIFIED`, `BLOCKED` |
| Real-world claim | `NOT_PROVEN` / `PROVEN` (currently always `NOT_PROVEN`) |

Do not mix these concepts.

- **Local compatibility is not real-client compatibility.**
- **Capture validation is not server compatibility.**
- **Synthetic tests do not prove Destiny client interoperability.**
- **Observed does not mean understood.**
- **Implemented does not mean compatible.**
- **Unknown remains unknown until evidence changes it.**

Hypothesis does not auto-promote to Confirmed. Observed does not auto-promote to Implemented. Implemented does not imply Real Client. Local TCP does not imply Real Server.

## Compatibility scopes

| Scope | Meaning |
| ----- | ------- |
| `OFFLINE_CAPTURE` | Validated against offline captures |
| `SYNTHETIC_LOCAL` | Synthetic fixtures / unit tests |
| `LOCAL_TCP` | Localhost TCP harness |
| `EXTERNAL_BOUNDARY` | Local external-client boundary |
| `REAL_CLIENT` | Real Destiny client (not proven) |
| `REAL_SERVER` | Real Destiny / Bungie server (not proven) |

`VERIFIED` combined with `REAL_CLIENT` / `REAL_SERVER` is rejected unless real evidence exists (none today → counts stay at 0).

## Evidence model

Safe references only (no payloads, keys, tokens, credentials):

- capture `20260529-003132`
- capture `20260608-231100`
- local synthetic tests
- local replay
- external boundary
- observation harness

## Current matrix

Single source of truth: `get_compatibility_matrix()` in `network/src/compatibility_matrix.rs`.

Areas include framing, TCP stream, handshake, session login/crypto, encrypted handshake, NAT, keepalive, codec/dispatch/state, local server, compatibility client, external boundary, observation harness, UDP transport, gameplay networking, SignOn, real Destiny client/server.

All **28** `EXPECTED_MESSAGE_IDS` are represented as message entries. Opaque / variable-length IDs (`0x10`/`0x11`, `0x2A`/`0x2B`, `0x7B`, `0xAB`, …) keep limited/unknown semantics — no invented meaning.

## Verified offline capabilities

Examples (evidence + implementation + verification within offline/local scopes):

- BAP framing + stream decoder
- TCP stream / fragmentation
- `0x1E`/`0x1F`, `0x19`/`0x1A`, `0x79`/`0x7A`, `0xFA`/`0xFB`
- `SessionCryptoContext` (capture-scoped)
- Local server, compatibility client, external boundary, observation harness

## Observed but unresolved capabilities

- Ambient UDP in captures (ports such as 3074/3075 are **not** asserted as Destiny gameplay transport)
- NAT candidates `0x12E`/`0x12F` — structure/correlation limited
- Variable / opaque inventory messages — semantics limited/unknown

## Blocked capabilities

- SignOn (no real auth / live connection)
- Gameplay networking / UDP gameplay
- Real Destiny client compatibility
- Real Destiny server compatibility

Each `BLOCKED` entry has a `blocking_reason`.

## Real-client limitations

`REAL_DESTINY_CLIENT` is `NOT_PROVEN` / `NOT_VERIFIED`. Local and synthetic success does not prove Destiny client interoperability.

`real_client_verified: 0`

## Real-server limitations

`REAL_DESTINY_SERVER` is `NOT_PROVEN` / `NOT_VERIFIED`. Local TCP and capture validation do not prove server compatibility.

`real_server_verified: 0`

## Rules against semantic overreach

- No invented message or payload semantics.
- `UNKNOWN` cannot carry an invented `semantic_claim`.
- Fixture/export contains no secrets.
- M4.9 does not connect to Bungie or Destiny servers.
- M4.9 does not use real credentials, modify the Destiny executable, inject/hook, bypass DRM/anti-cheat, or implement UDP gameplay.

## How to run verification

```bash
cd network
cargo run -- compatibility-matrix-verify
cargo run -- compatibility-matrix-report
```

Expected:

```text
COMPATIBILITY_MATRIX: VERIFIED
real_client_verified: 0
real_server_verified: 0
```

Fixtures:

- `fixtures/compatibility_matrix/compatibility_matrix_safe.json`
- `fixtures/compatibility_matrix/compatibility_matrix_negative.json`

## How to add future evidence

1. Update evidence only when new offline captures or tests exist.
2. Keep dimensions separate; never auto-promote Hypothesis → Confirmed.
3. Add evidence_refs / verification_refs for Confirmed / Verified.
4. Keep real-client and real-server claims `NOT_PROVEN` until genuine evidence exists.
5. Re-run `compatibility-matrix-verify` and full regression suite.
