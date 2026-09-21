# Unknown registry (M4.1)

Prioridades de **investigación técnica** (qué bloquea qué tipo de implementación).
No valoran “importancia del protocolo Destiny”.

## HIGH

| ID | Description | Blocks |
| -- | ----------- | ------ |
| UNK-UDP | UDP/gameplay transport (umbrella) | gameplay / multiplayer |
| UNK-UDP-TRANSPORT | Whether a Destiny gameplay/session UDP transport exists beyond ambient DNS/SSDP/3074 | UDP stack design |
| UNK-UDP-FRAMING | UDP datagram framing / multiplexing | UDP decoder |
| UNK-UDP-SESSION-BINDING | How (if at all) UDP binds to BAP TCP session / tokens | session join |
| UNK-UDP-PAYLOAD | Meaning of non-DNS UDP payloads (e.g. short 3074 frames) | message handlers |
| UNK-UDP-SEQUENCING | Reliability / sequence / ack model | loss recovery |
| UNK-UDP-LOSS | Loss tolerance and retransmission | gameplay sync |
| UNK-UDP-REORDERING | Reorder handling | gameplay sync |
| UNK-UDP-NAT | Relation of BAP `0x12E`/`0x12F` to any UDP path | NAT traversal |
| UNK-PAYLOAD | Payload semantics of critical post-session messages | message dispatch / local server |
| UNK-SERVER-STATE | Server-side state expectations after startup | interoperable local server |
| UNK-PLATFORM | PS4/Xbox/PC equivalence | cross-platform claims |

## MEDIUM

| ID | Description | Blocks |
| -- | ----------- | ------ |
| UNK-CONTEXT | Meaning of BAP `context` u32 | request correlation |
| UNK-KEEPALIVE-MS | Keepalive wall-clock period | timing-accurate keepalive |
| UNK-AAD | AAD beyond empty-in-verified-captures | general GCM claims |
| UNK-VARIABLE | Variable-length payloads (`0x7B`, `0xAB`, …) | full payload parsers |
| UNK-REKEY | AES-GCM rekey / resync | long-lived sessions |

## LOW

| ID | Description | Blocks |
| -- | ----------- | ------ |
| UNK-CAPTURE-SPECIFIC | Roles of capture-specific IDs (`0x10`/`0x11`/`0x2A`/`0x2B`) | complete coverage |

## Related

- [unknowns.md](unknowns.md) (historical open questions)
- [protocol-spec-v0.1.md](protocol-spec-v0.1.md)
- [udp-evidence.md](udp-evidence.md) (M4.3 — none of the UNK-UDP-* entries are resolved)
