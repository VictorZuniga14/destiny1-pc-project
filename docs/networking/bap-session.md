# BapSession (M2.6)

Offline BAP session layer for Destiny 1 network research.

## BapSession

`BapSession` encapsulates:

```text
BapSession
├── BAP framing
├── clear frames
├── encrypted frames
├── SessionCryptoContext
└── AES-GCM
```

**Does:**

- parse/serialize documented BAP frames from bytes;
- decode `kind=2` clear bodies into typed `msg_id` / `context` / payload bytes;
- decrypt `kind=1` bodies with `SessionCryptoContext` + `decrypt_aes_gcm`;
- keep independent C→S / S→C nonce counters;
- run mass offline validation against capture fixtures.

**Does not:**

- open sockets / TCP / UDP;
- implement a server or client transport;
- perform SignOn / Bungie login;
- implement Destiny gameplay, matchmaking, or services;
- print keys, nonces, ciphertext, tags, or plaintext.

Transport that feeds bytes into `BapSession` is out of scope for M2.6.

## Framing

Documented outer layout ([framing-bap.md](framing-bap.md)):

```text
[0x01][kind:u8][body_len:u32 BE][body...]
```

Parser validates magic `0x01`, declared `body_len`, and full body availability. Incomplete frames are errors (no silent truncation).

## Clear

`kind = 2`:

```text
[msg_id:u16 BE][context:u32 BE][payload...]
```

Payload bytes are kept opaque. Clear frames **do not** consume a GCM nonce.

## Encrypted

`kind = 1`:

```text
[tag:16][ciphertext...]
```

The nonce is **not** carried in the frame. It comes from `SessionCryptoContext` for the caller-supplied direction.

## Crypto

```text
BapSession
    ↓
SessionCryptoContext
    ↓
nonce (per direction)
    ↓
AES-GCM (AAD empty for validated frames)
    ↓
decoded offline frame
```

`BapSession` does **not** use `gcm_sequence` to generate nonces. `SessionCryptoContext` is the single source of truth (M2.5).

### Nonce consumption (API semantics)

| Input | Nonce advance? |
| ----- | -------------- |
| Framing invalid / truncated | No |
| `kind=2` clear | No |
| Opaque / unknown kind | No |
| `kind=1` with empty ciphertext | No (structural reject) |
| `kind=1` structurally valid, then GCM decrypt | Yes — **before** decrypt; **no rollback** on auth failure |

This matches M2.4d / d1-re sequencing: a failed GCM still advances the direction counter so the next frame stays aligned.

Direction is **mandatory** for encrypted frames and is never inferred from the wire.

## Direction

C→S and S→C use independent counters and bases:

- C→S base = `session_nonce` with last byte XOR `1`
- S→C base = `session_nonce` (Identity)

See [gcm-channel-validation.md](gcm-channel-validation.md).

## Offline scope

```text
CONFIRMED offline:
  bytes → BapSession → framing → SessionCryptoContext → AES-GCM → decoded frame

NOT in M2.6:
  sockets, TCP transport, UDP, BapServer, GameServer, LobbyServer,
  matchmaking, activity server, peer networking, gameplay
```

## CLI

```bash
cargo run -- bap-session-verify ../evidence/local/bap_session_verify.json
```

Material is gitignored. Report prints metadata only (`frames_seen`, clear/encrypted counts, decrypt success/fail, `nonce_state_valid`, `result`).

## Evidence status

### CONFIRMED (capture `20260529-003132`)

- Outer BAP framing `0x01` / kind / body_len.
- Clear `kind=2` layout for handshake/login messages.
- Encrypted `kind=1` = tag(16) + ciphertext; nonce from session context.
- Session key + nonce from `0x1A` plaintext (M2.3).
- AES-GCM with empty AAD for validated encrypted frames.
- Independent C→S / S→C counters; clear frames do not advance them.
- Mass offline decode via `BapSession` against PCAP-derived wire hex.

### EXTERNAL EVIDENCE

- d1-re JSONL correlation (`frame_offset`, `frame_order`, post-decrypt `msg_id`).
- PCAP wire bytes for frames where material was extractable.

### UNKNOWN

- AAD non-empty cases.
- Rekey / resync mid-session.
- Platforms other than this PS3 capture.
- Full semantic meaning of every clear/encrypted payload.
- Frames present only in JSONL without recoverable PCAP wire (`wire_material = UNKNOWN` — not counted as decrypt failures).

## Related

- [gcm-channel-validation.md](gcm-channel-validation.md) — M2.4d sequence
- [first-encrypted-frame.md](first-encrypted-frame.md) — M2.4a
- [framing-bap.md](framing-bap.md) — framing spec
