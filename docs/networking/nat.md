# NAT report

## Mensajes

| ID | Nombre |
| -- | ------ |
| `0x12E` | `nat-report` |
| `0x12F` | `nat-report-status` |

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: BAP_NAMES
```

## CONFIRMED

- Los IDs y nombres existen en el decryptor público de `d1-re`.
- Se tratan como mensajes BAP (mismo espacio de `msg_id` que handshake/session/keepalive).

## UNKNOWN

- Payload / campos.
- Dirección en wire.
- Qué información NAT reportan (IPs públicas, puertos, tipo de NAT, etc.).
- Relación exacta con apertura de sockets, STUN-like behavior, o relays.

## UDP gameplay / physics — UNKNOWN

**No afirmar** que `0x12E` / `0x12F` sean el gameplay UDP.

```text
UDP gameplay   = UNKNOWN
UDP physics    = UNKNOWN
peer networking = UNKNOWN
NAT traversal de bajo nivel = UNKNOWN
```

Estos mensajes aparecen como **nombres** en el protocolo BAP (TCP en la evidencia actual). Eso no demuestra:

- que el movimiento/disparos viajen en estos mensajes;
- que exista o no un canal UDP separado;
- cómo se hace hole punching.

Ver [unknowns.md](unknowns.md) y [protocol-overview.md](protocol-overview.md).

## Qué no afirmar

- “NAT report = multiplayer UDP”.
- Layouts de IP/puerto dentro del payload sin evidencia de parseo.

## REQUIRES TEST

- ~~Ubicar `0x12E`/`0x12F` en timelines JSONL y correlacionar con notas `LOG` de capturas.~~ → hecho en M4.3 (temporal only).
- ~~Buscar en los mismos PCAPs tráfico UDP concurrente~~ → hecho en M4.3: ver [udp-evidence.md](udp-evidence.md).

M4.3: NAT BAP messages can appear **without** concurrent non-DNS UDP; closest 3074 traffic (when present) was ~80s **before** session — not causal proof.
