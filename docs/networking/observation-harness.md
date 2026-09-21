# M4.8 — Real Client Observation Harness

## Purpose

M4.8 is an **observation and comparison harness**.

It records safe structural metadata from BAP session traces (fixtures or local `ExternalClientBoundary` events) and compares them against the project's confirmed local model. It answers questions such as: which frames appear, in what order, direction, type, length, observed state, and where the observation diverges from the reference scenarios.

M4.8 does **not** turn observations into protocol implementations.

## Architecture

```text
External/Provided Traffic
        ↓
Observation Adapter
        ↓
ExternalClientBoundary / BapStreamDecoder  (existing stack — reused, not rebuilt)
        ↓
Safe Observation Trace (metadata only)
        ↓
Protocol Analyzer
        ↓
Model Diff
        ↓
Classification (Observed / Structural / Hypothesis / Confirmed / Unknown)
```

Flow for boundary integration:

```text
ExternalClientBoundary → safe events → ObservationTrace → ObservationAnalyzer → ObservationDiff
```

No second TCP layer. No external network. Bytes stay out of the observation trace.

## Observation model

Core types live in `network/src/observation.rs`:

- `ObservedFrame` — metadata only: `connection_id`, `frame_index`, `direction`, `kind`, `body_len`, optional legitimate `message_id`, observed `protocol_state`, optional relative timestamp, optional `SafeFingerprint`.
- `ObservationEvent` — `ConnectionStarted`, `FrameObserved`, `StateObserved`, `ProtocolMismatch`, `ConnectionClosed`, `ObservationError` (all metadata-only).
- `ObservationSource` — `FixtureObservationSource` and boundary-event adaptation; no live external sockets.

Payloads, plaintext, ciphertext, keys, tokens, and credentials are **not** stored by default.

## Safe trace

`network/src/observation_trace.rs` serializes/deserializes JSON/JSONL traces with fields such as:

`trace_version`, `capture_id`, `frame_index`, `direction`, `kind`, `message_id`, `body_len`, `state`, `relative_time_ms`, `fingerprint`, `event`.

Sensitive fields from older or hostile inputs are rejected (see Sensitive data policy). Secrets and cryptographic bytes are never copied into the new format.

## Classification levels

`network/src/protocol_observation.rs`:

| Level | Meaning |
| ----- | ------- |
| **Observed** | Appeared in the source (e.g. registry ID without confirmed startup/keepalive identity role). |
| **Structural** | Byte/length/order pattern without demonstrated semantic meaning (e.g. frame without `message_id`). |
| **Hypothesis** | Interpretation not yet confirmed (e.g. registry IDs diverging from confirmed startup sequence). |
| **Confirmed** | Already confirmed by existing project evidence (stable startup IDs, `0xFA`/`0xFB` ID identity). |
| **Unknown** | Insufficient evidence — e.g. ID not in `EXPECTED_MESSAGE_IDS`. |

**Never** auto-promote `Observed` or `Structural` (or `Hypothesis`) to `Confirmed`. Confirmed requires explicit evidence already present in the project (multi-capture / protocol registry rules), not analyzer invention.

Observation and semantics stay separate. Unknown IDs (example: `0xEE` when not in the registry) remain `Unknown` — they are not labeled request, response, keepalive, NAT, or gameplay.

## Diff engine

`network/src/observation_diff.rs` compares observation vs expected scenario and reports structural differences:

`MissingFrame`, `UnexpectedFrame`, `DirectionMismatch`, `LengthMismatch`, `OrderMismatch`, `StateMismatch`, `UnexpectedClose`, `UnknownMessage`, plus crypto processing failure as metadata (`CryptoProcessingFailure`) without exposing key material.

Summary form:

```text
EXPECTED: 0x1E → 0x1F → 0x19 → 0x1A
OBSERVED: 0x1E → 0x1F → 0x19 → 0x1A → 0x79
DIFF: additional frame 0x79
```

Divergence is reported; it is **not** asserted to mean client error. Diffs do **not** generate protocol code.

## Reference scenarios

`network/src/observation_scenarios.rs` — derived only from confirmed/documented evidence:

| Scenario | Basis |
| -------- | ----- |
| `startup` | `0x1E → 0x1F → 0x19 → 0x1A → 0x79 → 0x7A → 0x12E → 0x12F` |
| `session_establishment` | Clear handshake portion |
| `encrypted_handshake` | `0x79` / `0x7A` |
| `active_keepalive` | `0xFA` / `0xFB` (intervals observational only) |
| `unknown_message` | Non-registry IDs remain Unknown |

Startup is a local reference sequence, not a universal requirement for every future session.

## Sensitive data policy

Trace parsers reject or refuse sensitive keys such as:

`key`, `session_key`, `token`, `credential`, `password`, `authorization`, `private_key`, `payload`, `payload_hex`, and equivalents.

These must not appear in the observation model. Tests assert rejection.

## Unknown handling

- Do not invent meaning for unknown message IDs.
- Report as `Unknown` / `Observed` as appropriate for registry membership.
- Keepalive timing stays observational — not a universal rule.
- Crypto failures: report `CryptoProcessingFailure` metadata only; no key recovery.

## Fingerprint

`SafeFingerprint` is a non-reversible cryptographic hash (SHA-256 truncated) for equality/difference correlation only. It must not be used to recover payloads.

## Limitations

M4.8 is an observation and comparison harness.

M4.8 does not connect to Bungie.

M4.8 does not connect to Destiny servers.

M4.8 does not modify the Destiny executable.

M4.8 does not implement injection or hooks.

M4.8 does not bypass authentication, DRM or anti-cheat.

M4.8 does not implement UDP gameplay.

M4.8 does not recover credentials or session secrets.

M4.8 does not automatically infer protocol semantics from observations.

M4.8 does not prove compatibility with the real Destiny client.

## CLI

```text
cargo run -- observation-verify
cargo run -- observation-diff <expected.json> <observed.json>
```

Fixtures: `network/fixtures/observation/`.

## Future external-client work

Later milestones may expand observation coverage against additional offline captures or local boundary scenarios. They must keep the same bans: no Bungie, no real Destiny servers, no executable modification, no injection/hooks, no credential/session-secret recovery, no UDP gameplay, and no automatic promotion of hypotheses to confirmed protocol semantics.
