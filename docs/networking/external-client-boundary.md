# External Client Compatibility Boundary

M4.7 — localhost TCP ingress boundary for future external BAP clients.

## Purpose

Provide a clean edge between an external BAP client harness and the existing
local protocol stack without duplicating framing, crypto, or message semantics.

## Scope

```text
External Client → TCP 127.0.0.1 → ExternalClientBoundary
  → BapStreamDecoder → StatefulBapSession → MessageCodec / ProtocolState / ResponsePolicy
```

M4.7 does **not**:

- connect Destiny 1 or inspect/modify its executable
- connect to Bungie
- implement SignOn / real auth / credentials / tokens
- implement UDP, NAT, matchmaking, gameplay, or physics

## Architecture

`ExternalConnectionState` (TCP/boundary lifecycle) is separate from
`ProtocolState` (BAP execution policy, M4.5).

## TCP listener

`ExternalClientListener` binds only to `127.0.0.1` (or loopback). Rejects
`0.0.0.0`, `::`, and external IPs/hostnames.

## Connection lifecycle

`Accepted → Reading → ProtocolActive → Closing → Closed`

## BAP integration

Reuses `BapStreamDecoder`, `StatefulBapSession`, `MessageCodec`, `ResponsePolicy`.
No second BAP parser.

## Event model

`ExternalBoundaryEvent`: ConnectionAccepted, BytesReceived, FrameRecovered,
FrameRejected, ProtocolEvent, ConnectionError, ConnectionClosed — safe metadata only.

## Safe logging

No payload hex, plaintext, ciphertext, keys, nonce, HMAC, tokens, or credentials.

## Multi-client isolation

Independent decoder, protocol state, crypto, counters, and events per connection.

## Error handling

Framing / protocol / crypto / limit errors → FrameRejected / ConnectionClosed — no panic.

## Test harness

`ExternalBoundaryHarness` + `BoundaryTestClient` (std::net blocking). May drive
handshake via `BapCompatibilityClient`.

## Limitations

Local compatibility boundary only. Does not prove Destiny executable compatibility.

## Future external-client work

Later milestones may attach a real community client binary — still localhost-only
until explicitly redesigned with evidence.

## Verify

```bash
cargo run -- external-boundary-verify
```

Expected: `EXTERNAL_BOUNDARY_VERIFY: VERIFIED`
