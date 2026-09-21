# Message Codec (M4.4)

## Status

```text
M4.4 DONE
```

## Architecture

```text
TCP bytes
   ↓
BapStreamDecoder
   ↓
BapSession          (decrypt if kind=1)
   ↓
DecodedBapFrame
   ↓
MessageCodec        (logical body only)
   ↓
BapMessage
   ↓
MessageDispatcher   (observation events)
```

The codec does **not** implement framing (`0x01` / kind / body_len), AES-GCM, CBC/HMAC, sockets, or PCAP.

## Message registry

Central table in `message_registry.rs` over the 28 IDs from `EXPECTED_MESSAGE_IDS`.

Safe export: `network/fixtures/message_codec/message_registry_safe.json`.

| Field | Meaning |
| ----- | ------- |
| id / direction | Typical wire direction (hint) |
| codec | Codec variant name |
| status | `CONFIRMED_STRUCTURE` / `OPAQUE_KNOWN` / `UNKNOWN` |
| name_source | `EXTERNAL_REFERENCE` when name comes from message-matrix / d1-re |

## Known messages

Dedicated codecs:

| ID | Variant | Status |
| -- | ------- | ------ |
| 0x1E | DestinyServiceHandshakeRequest | OPAQUE_KNOWN |
| 0x1F | DestinyServiceHandshakeResponse | OPAQUE_KNOWN |
| 0x19 | SessionLoginRequest | OPAQUE_KNOWN |
| 0x1A | SessionLoginResponse | CONFIRMED_STRUCTURE (+ opaque fallback) |
| 0x79 | EncryptedHandshakeRequest | OPAQUE_KNOWN (plaintext body) |
| 0x7A | EncryptedHandshakeStatus | OPAQUE_KNOWN |
| 0x12E | Message0x12E | OPAQUE_KNOWN |
| 0x12F | Message0x12F | OPAQUE_KNOWN |
| 0xFA | Message0xFA | OPAQUE_KNOWN |
| 0xFB | Message0xFB | OPAQUE_KNOWN |

Opaque = payload preserved without inventing field names.

## Unknown messages

`UnknownBapMessage { id, context, direction, payload }` keeps raw bytes in memory.

- Not printed by default (`Display` shows length only).
- Not written to safe fixtures.
- Encode/decode is byte-for-byte.

## 0x1A structure

From M2.1–M2.3 (structural only; **no decrypt in codec**):

```text
u16_be prefix          // meaning UNKNOWN
u32_be record_len      // >= 0x30
16-byte IV
ciphertext             // record_len - 0x30
32-byte HMAC
```

Validation checks lengths / alignment. Crypto stays in `network/src/crypto/`.

Harness / synthetic short payloads (e.g. M4.2 `SIM_1A`) decode as known `SessionLoginResponse` with `record=None` and `raw_payload` preserved.

## Encrypted handshake messages

`0x79` / `0x7A` codecs operate on **already decrypted** plaintext bodies (id/context stripped by `BapSession`). No nonce/key work here.

## Encode/decode rules

- `encode_message` → logical payload bytes only.
- `decode(encode(m))` preserves payload for known opaque + unknown.
- Structured `0x1A` encode rebuilds from `SessionLoginResponseRecord` when present.

## Validation

Errors: `InvalidPayloadLength`, `InvalidFieldLength`, `InvalidRecordLength`, `UnexpectedMessageId`, `MalformedMessage`, `UnsupportedMessage`. No panics on bad input.

## Dispatcher

`MessageDispatcher` emits:

```text
MessageObserved
StartupMessageObserved
SessionLoginObserved
EncryptedHandshakeObserved
NatMessageObserved
KeepAliveObserved
```

Results: `Handled` / `Observed` / `Unknown`.

Does **not** mutate the M3.4 observational state machine.

## Capture validation

```bash
cargo run -- message-codec-verify
# or
cargo run -- message-codec-verify fixtures/multi_capture/manifest.json
```

```text
MESSAGE_CODEC_VERIFY: VERIFIED
```

Scans decrypted JSONL when present; never prints payloads.

## Limitations

```text
M4.4 does NOT invent payload field semantics.
M4.4 does NOT decrypt 0x1A / AES-GCM.
M4.4 does NOT implement gameplay handlers.
M4.4 does NOT change UDP evidence (M4.3 closed).
M4.4 does NOT connect to Bungie or Destiny.
```

## Unknown semantics

Names in `messages.rs` remain **EXTERNAL_REFERENCE**. Structural codecs do not promote them to CONFIRMED Destiny meaning.
