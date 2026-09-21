# Destiny 1 BAP Protocol Specification v0.1

> **v0.1** is an engineering specification based on observed evidence in this
> project. It is **not** an official Bungie specification.

## Scope

Document what M1–M3.4 have validated offline for PS3 captures:

```text
20260529-003132
20260608-231100
```

Does **not** cover: live SignOn client, Bungie connectivity, UDP/gameplay,
production authentication, or a Destiny server.

## Evidence policy

| Label | Meaning |
| ----- | ------- |
| CONFIRMED | Reproduced offline against verified capture material |
| OBSERVED | Directly seen in bytes / sequences |
| STRUCTURAL_HYPOTHESIS | Plausible structure; not semantic confirmation |
| EXTERNAL_REFERENCE | Name/docs from messages.rs / d1-re / matrix |
| UNKNOWN | Insufficient evidence |

## Verified captures

| Capture | Pipeline frames (approx) | Status |
| ------- | ------------------------ | ------ |
| 20260529-003132 | 128 | VERIFIED |
| 20260608-231100 | 126 (first BAP session) | VERIFIED |

Cross-capture: `VERIFIED_MULTI_CAPTURE` (M2.9).

## Transport

- Documented session core: TCP + BAP (docs).
- `TcpByteSource`: **OFFLINE/LOCAL TRANSPORT IMPLEMENTATION** (std::net, read-only).
- Serves local TCP replay/testing only — **no** Bungie host/port defaults.
- UDP: UNKNOWN / not implemented.

## BAP framing

CONFIRMED:

```text
[0x01]
[kind:u8]
[body_len:u32 BE]
[body...]
```

Kinds: `1` encrypted, `2` clear.

Clear body:

```text
[msg_id:u16 BE]
[context:u32 BE]
[payload...]
```

`MAX_BODY_LEN = 4 MiB` = **IMPLEMENTATION_LIMIT** (not a Destiny protocol claim).

## Clear frames / Encrypted frames

Clear: offline parse via `BapSession` / framing.

Encrypted (kind=1): opaque on wire until session material; decrypt via AES-GCM
with `SessionCryptoContext` (verified captures).

## Session login (`0x1A`)

CONFIRMED for verified capture evidence:

- direction S2C, kind 2, context 1, payload_len 86
- prefix u16 BE = 200; record_len u32 BE = 80
- IV 16 + ciphertext 32 + HMAC 32
- AES-CBC PKCS#7 + HMAC-SHA256
- HMAC input: `u32_be(record_len) || IV || ciphertext`
- HMAC/decrypt/padding validated; plaintext 32 / unpadded 28

`nonce[12] || session_key[16]` layout: **STRUCTURAL_HYPOTHESIS**.

Keys from SignOn-derived **local evidence only** — never committed.

## Session crypto

Inputs: session_key 16, session_nonce 12.

- C2S base: nonce with last byte XOR 1
- S2C base: identity
- Independent counters; first nonce = base, then increment

Classification: **CONFIRMED_FOR_VERIFIED_CAPTURES** (not UNIVERSAL_PROTOCOL_RULE).

## AES-GCM

AES-128-GCM; key = session key; nonce 12 bytes.

AAD was **empty** in all currently verified frames.  
General AAD behavior remains **UNKNOWN**.

First frames (OBSERVED): `0x79` body 22 (16+6); `0x7A` body 24 (16+8).  
Channel validation: startup 8/8; sessions 124/124 and 122/122 VERIFIED.

## Nonce model

See Session crypto. CONFIRMED_FOR_VERIFIED_CAPTURES.

## Startup sequence

OBSERVED / STABLE_CROSS_CAPTURE:

```text
START
 → 0x1E → 0x1F → 0x19 → 0x1A → 0x79 → 0x7A → 0x12E → 0x12F
 → POST_STARTUP
```

Structural label: `STABLE_STARTUP_SEQUENCE` (not LOGIN/AUTHENTICATED).

## State machine

M3.4 nodes: START, STARTUP_SEQUENCE, POST_STARTUP, REPEATING_CLUSTER_01,
BRANCH_CAPTURE_A_01, BRANCH_CAPTURE_B_01.

Divergence after common prefix (index 25 in verified pair): A `0x0A` / B `0xAB`.

## Message matrix

28 IDs represented in `fixtures/protocol_spec/protocol_spec_safe.json`.  
See also [message-matrix.md](message-matrix.md) (EXTERNAL_REFERENCE names).

## Implementation readiness

| Component | Readiness |
| --------- | --------- |
| BAP framing / stream / GCM / nonce / session-login crypto | READY_OFFLINE |
| TCP ByteSource | READY_FOR_LOCAL_TEST |
| Startup state machine | READY_OFFLINE |
| Message dispatch | PARTIALLY_READY |
| SignOn / authentication / UDP / gameplay | BLOCKED |

**Understood ≠ interoperable.** Offline YES does not imply server-compatible.

## Unknown registry

See [unknown-registry.md](unknown-registry.md).

## External references

`messages.rs` / d1-re / message-matrix names are EXTERNAL_REFERENCE only.

## Security / secrets policy

No session keys, MAC keys, SignOn tokens, or credentials in the repository.
Local verification material stays under `evidence/local/` (gitignored).

## Limitations

- PS3 evidence only for verified captures.
- No production SignOn client.
- No Bungie connectivity.
- No UDP/gameplay.
- No claim of complete payload schemas.

## Machine-readable export

```bash
cargo run -- protocol-spec-verify fixtures/multi_capture/manifest.json
```

→ `fixtures/protocol_spec/protocol_spec_safe.json`  
Result: `VERIFIED_PROTOCOL_SPEC`.
