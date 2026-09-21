# Stateful Local BAP Server

M4.5 — local execution state machine for the localhost BAP compatibility server.

## Scope

This milestone adds **explicit protocol state**, centralized transitions, per-connection
`StatefulBapSession`, and a deterministic **response policy** on top of M4.2–M4.4.

Everything remains:

```text
localhost
offline
synthetic
deterministic
```

Out of scope:

- Bungie / Destiny / Internet
- real authentication, matchmaking, gameplay, physics
- UDP / NAT traversal / world state
- inventing message semantics beyond documented evidence

## Local protocol states

`ProtocolState` is a **local implementation policy**. It is **NOT** claimed to represent
Bungie's internal server state machine.

States:

- `Connected`
- `WaitingForServiceHandshake`
- `ServiceHandshakeComplete`
- `WaitingForSessionLogin`
- `SessionEstablished`
- `WaitingForEncryptedHandshake`
- `EncryptedChannelEstablished`
- `Active`
- `Closing`
- `Closed`

## Transition rules

All advances go through `protocol_state::transition` (plus accept/close helpers).
Connection code must not assign `server.state = ...` ad hoc.

Normal local sequence:

```text
CONNECTED
  → 0x1E → SERVICE_HANDSHAKE_COMPLETE (+ synthetic 0x1F)
  → 0x19 → SESSION_ESTABLISHED (+ synthetic 0x1A)
  → 0x79 → WAITING_FOR_ENCRYPTED_HANDSHAKE (+ synthetic 0x7A)
  → ENCRYPTED_CHANNEL_ESTABLISHED
  → 0x12E / 0xFA / other observed → ACTIVE
```

## Message handling

Uses existing codecs (`message_codec`) and `MessageDispatcher` (observational).
Handshake IDs validate direction; wrong direction → `InvalidDirection` (no auto-reply).

## Response policy

`ResponsePolicy` maps `(state, inbound message) → ResponseAction`:

| Inbound | State | Action |
| ------- | ----- | ------ |
| 0x1E | WaitingForServiceHandshake | SendClear 0x1F |
| 0x19 | ServiceHandshakeComplete | SendClear 0x1A |
| 0x79 | SessionEstablished | SendEncrypted 0x7A |
| 0xFA | Encrypted/Active | optional synthetic 0xFB |
| 0x12E / 0x12F | Encrypted/Active | ObserveOnly |
| unknown | (default) | ObserveOnly / None |

No invented replies for undocumented IDs.

## Synthetic crypto

`SyntheticSessionMaterial` uses deterministic test key/nonce only
(`LOCALSERVER_KEY!` / `LOCALNONCE12`). Never real SignOn material or capture secrets.
Reuses `SessionCryptoContext` / `BapSession` — no duplicated AES-GCM stack.

## Error handling

Typed errors: `UnexpectedMessage`, `InvalidDirection`, `InvalidState`, `InvalidMessage`,
`CryptoNotEstablished`, `HandshakeIncomplete`, `AlreadyClosed`, `InvalidTransition`.
Invalid sequences reject deterministically without panic.

## Unknown messages

Default `UnknownPolicy::Observe` — dispatch observation, no automatic response.
Optional `Reject` for tests only.

## Multi-client isolation

Each TCP connection owns its own `ProtocolState`, crypto context, nonce counters,
and dispatcher. Concurrent clients do not share mutable session state.

## Negative cases

Covered: 0x19 before 0x1E; 0x79 early; 0x7A before 0x79; 0x12E before session;
malformed logical frame → `InvalidMessage`; unknown → Observed.

## Limitations

```text
This state machine is a local implementation policy.

It is NOT claimed to represent Bungie's internal server state machine.

Message semantics remain limited to documented evidence.

No gameplay state is implemented.

No UDP behavior is implemented.

No external service is contacted.
```

## Relationship to M3.4

M3.4 (`state_machine.rs`) remains an **observational** state machine over capture evidence.
M4.5 is a **server execution** state machine for localhost testing.
They are intentionally separate and must not be merged.

## Verify

```bash
cargo run -- stateful-server-verify
```

Expected: `STATEFUL_SERVER_VERIFY: VERIFIED`
