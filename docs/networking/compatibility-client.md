# Local BAP Compatibility Client

M4.6 — localhost client harness that completes a synthetic BAP session against
`LocalBapServer`.

## Scope

```text
BapCompatibilityClient ↔ LocalBapServer on 127.0.0.1 (TCP only)
```

This client is a **local compatibility harness**.

It is **NOT** the Destiny 1 client.

It does **NOT** implement Destiny gameplay.

It does **NOT** connect to Bungie.

It does **NOT** implement authentication against Bungie.

It does **NOT** implement UDP.

It does **NOT** implement NAT traversal.

Its cryptographic material is **synthetic**.

Its protocol state machine is a **local compatibility model**.

It does **not** prove compatibility with the real Destiny 1 executable.

## Architecture

```text
BapCompatibilityClient
  TCP (localhost only)
  BapStreamDecoder
  BapSession / SessionCryptoContext
  MessageCodec
  ClientProtocolState
        │
        ▼
LocalBapServer (M4.5 StatefulBapSession)
```

`BapReplayClient` (M4.2) remains for fixture-driven replay. Do not merge the two.

## Client states

`ClientProtocolState` (client perspective; separate from server `ProtocolState`):

- Disconnected, Connected
- ServiceHandshakeSent, ServiceHandshakeComplete
- SessionLoginSent, SessionEstablished
- EncryptedHandshakeSent, EncryptedChannelEstablished
- Active, Closing, Closed

## Handshake

```text
CONNECT → 0x1E → 0x1F → 0x19 → 0x1A → crypto ready → 0x79 → 0x7A → ACTIVE
```

Payloads are synthetic and codec-encoded.

## Synthetic crypto

Centralized in `network/src/test_crypto_material.rs` (`SYNTHETIC_TEST_ONLY`):

- key `00..=0f`
- nonce `10..=1b`

C2S base = session_nonce with last byte XOR 1; S2C base = session_nonce (existing `SessionCryptoContext`).

Never log key/nonce bytes.

## Message handling

Uses `MessageCodec` + observational `MessageDispatcher`. Post-handshake: `0x12E`, optional keepalive `0xFA`/`0xFB`, unknown IDs observe-only.

## Chunking

`feed_bytes` / `BapStreamDecoder` reassemble split TCP writes and multiple frames per read.

## Multi-client behavior

Each client instance owns independent state, crypto, counters, decoder, dispatcher.

## Reconnect

New client instance starts `Disconnected`; counters reset to 0.

## Negative cases

Wrong key/nonce, tampered ciphertext, out-of-order expectations, encrypted-before-ready, external endpoints — typed errors, no panic.

## Event trace

`CompatibilityClientEvent` safe labels: event, message_id, direction, state — never secrets.

## Limitations

See Scope. Local policy only; not Bungie SM; no UDP/gameplay/external traffic.

## Security

```text
External network: NONE
Bungie: NONE
Destiny: NONE
Real credentials: NONE
Real session keys: NONE
UDP sending: NONE
Gameplay: NONE
```

## Verify

```bash
cargo run -- compatibility-client-verify
```

Expected: `COMPATIBILITY_CLIENT_VERIFY: VERIFIED`
