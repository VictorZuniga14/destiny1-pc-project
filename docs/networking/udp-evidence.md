# UDP Evidence (M4.3)

## Status

```text
M4.3 DONE
```

## Scope

```text
M4.3 does NOT implement UDP networking.
M4.3 does NOT prove UDP gameplay semantics.
M4.3 does NOT identify physics packets.
M4.3 does NOT implement NAT traversal.
M4.3 does NOT connect to Bungie.
M4.3 does NOT connect to Destiny.
M4.3 is read-only offline evidence analysis.
```

Produces a structured evidence base for deciding whether a future UDP milestone is justified.

## Captures

| Capture | Source | Notes |
| ------- | ------ | ----- |
| `20260529-003132` | `external/d1-re/captures/.../traffic.pcap` | PS3; Titan / inventory activity per LOG |
| `20260608-231100` | idem | LOG: solo/no-peer; no 3074 peer/world traffic |

Original PCAPs are **not** committed. Analysis is offline / read-only.

## Detection

Classic PCAP (Ethernet / IPv4 / UDP) scanned with a minimal offline parser (`parse_classic_pcap_udp`). No sockets. No `sendto`.

| Capture | Total UDP | DNS (53) | Non-DNS |
| ------- | --------- | -------- | ------- |
| 20260529-003132 | 65 | 52 | 13 (SSDP/1900 + 3074/3075) |
| 20260608-231100 | 4 | 4 | 0 |

## UDP flows

Flows labeled `UDP_FLOW_01`, `UDP_FLOW_02`, … (never `GAMEPLAY_FLOW`).

Capture A (simplified classes):

1. DNS port-pair flows — ambient
2. UDP/1900 SSDP `M-SEARCH` — ambient LAN discovery
3. UDP 3074↔3074 / 3074↔3075 — short payloads (4–16 B)

Capture B:

1. DNS only → non-session UDP: `UDP_NOT_OBSERVED_IN_CAPTURE`

## TCP correlation

BAP sessions exist on TCP in both captures (startup `0x1E`…`0x7A`, NAT `0x12E`/`0x12F`, keepalives, etc.).

UDP clusters in A complete **before** BAP `0x1E` (`BEFORE_SESSION`).

No UDP datagrams observed **during/after** the BAP session window in either capture.

## BAP correlation

Temporal proximity to `0x12D` / `0x0A` / `0xFA` / … was checked.  
**Correlation ≠ causality.**

In A, nearest 3074 packet to `0x12E`/`0x12F` is ~**80 seconds earlier** → not a close `TEMPORAL_CORRELATION_CANDIDATE`.

In B, `0x12E`/`0x12F` appear on BAP/TCP with **no** non-DNS UDP at all.

## NAT correlation

Prior docs name `0x12E`/`0x12F` as NAT-related BAP messages (TCP).

M4.3 finding:

```text
OBSERVED: NAT BAP messages can appear without concurrent UDP in-capture.
UNKNOWN: whether 0x12E/0x12F initialize, describe, or are unrelated to any UDP channel.
```

Do **not** claim `0x12E_INITIALIZES_UDP`.

## Payload structure

Safe exports store **SHA-256 + length + prefix metadata only**.

Structural notes (not semantics):

- SSDP payloads begin with ASCII `M-SEARCH` (ambient).
- 3074 payloads often share leading bytes; length small-variation — `STRUCTURAL_OBSERVATION`.

## Length analysis

| Class | Observation |
| ----- | ----------- |
| DNS | variable |
| SSDP | ~132–133 |
| 3074 | 4–16 (`small_variation`) |

Label: `STRUCTURAL_OBSERVATION` — not “physics packet”.

## Timing analysis

3074 cluster shows consecutive sub-second deltas (`BURST` heuristic).  
No tick-rate / physics-tick claims.

## Sequence candidates

Some 3074 trailing fields look monotonically increasing → `POSSIBLE_SEQUENCE_CANDIDATE` only.  
Never `CONFIRMED_COUNTER`.

## Cross-capture comparison

| Property | A | B | Stability |
| -------- | - | - | --------- |
| Any UDP | yes | yes | stable (DNS) |
| Port 3074 | yes | no | capture-specific |
| DNS | yes | yes | stable |
| UDP during/after BAP | no | no | stable |
| Non-DNS UDP | yes | no | divergent |

## Confirmed observations

```text
OBSERVED: UDP datagrams exist in capture 20260529-003132 (DNS + SSDP + 3074/3075).
OBSERVED: Capture 20260608-231100 has DNS-only UDP.
OBSERVED: BAP NAT messages (0x12E/0x12F) occur on TCP in both captures.
OBSERVED: No in-session UDP after BAP 0x1E in these two captures.
```

## Structural hypotheses

```text
STRUCTURAL_HYPOTHESIS: UDP/1900 traffic is LAN SSDP, not Destiny gameplay.
STRUCTURAL_HYPOTHESIS: UDP/3074 short messages may be platform/session ambient traffic; role UNKNOWN.
POSSIBLE_SEQUENCE_CANDIDATE: incrementing fields in some 3074 payloads.
```

## Unknowns

See [unknown-registry.md](unknown-registry.md):

`UNK-UDP-TRANSPORT`, `UNK-UDP-FRAMING`, `UNK-UDP-SESSION-BINDING`, `UNK-UDP-PAYLOAD`, `UNK-UDP-SEQUENCING`, `UNK-UDP-LOSS`, `UNK-UDP-REORDERING`, `UNK-UDP-NAT`.

## Limitations

- Only two PS3 captures inspected.
- Capture filters / interface completeness UNKNOWN.
- Absence of UDP in a capture ≠ “Destiny does not use UDP”.
- Port 3074 familiarity is **EXTERNAL_REFERENCE** / ambient knowledge — not Destiny proof.
- No payload semantics decoded.

## CLI

```bash
cargo run -- udp-evidence-verify fixtures/multi_capture/manifest.json
# UDP_EVIDENCE_ANALYSIS: VERIFIED
# UDP_OBSERVED: YES|NO
```

Safe exports: `network/fixtures/udp_evidence/udp_evidence_safe.json`, `cross_capture_safe.json`.
