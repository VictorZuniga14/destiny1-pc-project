# Networking — Destiny 1 PC Project

Documentación del protocolo de red basada en evidencia pública.

## Estado Milestone 1

```text
DONE — offline networking evidence pipeline validated against real capture (PS3 20260529-003132).
```

Ver [capture-20260529-003132-notes.md](capture-20260529-003132-notes.md) y [roadmap](../roadmap/README.md).

Siguiente tras M4.10: **M5** (no iniciado).

## Principio

> Evidence first, implementation second.

No asumir el protocolo. No inventar payloads. No tratar una plataforma como si representara a todas.

## Núcleo documentado (Milestone 1)

La evidencia pública de `kallsyms/d1-re` describe un flujo **PS3** cuyo núcleo es:

```text
SignOn HTTPS
     ↓
tokens + endpoints
     ↓
TCP
     ↓
BAP framing
     ↓
0x1E / 0x1F
     ↓
0x19 / 0x1A
     ↓
session key + nonce
     ↓
AES-GCM
     ↓
0x79 / 0x7A
0xFA / 0xFB
0x12D
0x12E / 0x12F
```

**TCP + BAP es el núcleo documentado.**

UDP (gameplay, physics, peer networking, NAT traversal de bajo nivel) queda:

```text
UNKNOWN
```

No se asume ni se implementa en Milestone 1.

## Plataforma de evidencia

| Plataforma | Estado |
| ---------- | ------ |
| PS3 | CONFIRMED (evidencia directa en `kallsyms/d1-re`) |
| PS4 | UNKNOWN |
| Xbox | UNKNOWN |
| PC | UNKNOWN |

Cualquier equivalencia entre plataformas requiere evidencia adicional.

## Niveles de confianza

Cada afirmación técnica debe clasificarse como:

| Nivel | Significado |
| ----- | ----------- |
| **CONFIRMED** | Observado o implementado de forma reproducible en la fuente citada |
| **PROBABLE** | Inferencia razonable a partir de evidencia parcial; no es un hecho cerrado |
| **UNKNOWN** | Sin evidencia suficiente |
| **REQUIRES TEST** | Hipótesis que necesita una prueba reproducible |

## Índice

| Documento | Contenido |
| --------- | --------- |
| [protocol-overview.md](protocol-overview.md) | Flujo de sesión mínimo observado |
| [signon-https.md](signon-https.md) | SignOn HTTPS y tokens |
| [framing-bap.md](framing-bap.md) | Framing BAP sobre TCP |
| [handshake.md](handshake.md) | `0x1E` / `0x1F` |
| [session.md](session.md) | `0x19` / `0x1A` overview |
| [session-login-response.md](session-login-response.md) | M2.1 / M2.2 / M2.3 — estructura `0x1A` + verificación CBC+HMAC offline |
| [session-crypto-key-material.md](session-crypto-key-material.md) | Origen de AES/HMAC keys (SignOn vs `0x1A`); por qué M2.3 no las tiene aún |
| [first-encrypted-frame.md](first-encrypted-frame.md) | M2.4a — primer `frame_kind=1` tras `0x1A` (captura `20260529-003132`) |
| [gcm-nonce.md](gcm-nonce.md) | M2.4b — reconstrucción del nonce candidato (XOR último byte C→S) |
| [gcm-first-frame.md](gcm-first-frame.md) | M2.4c — primer decrypt AES-GCM real de `0x79` |
| [gcm-channel-validation.md](gcm-channel-validation.md) | M2.4d — GCM bidireccional + nonce progression |
| [bap-session.md](bap-session.md) | M2.6 — `BapSession` offline + validación masiva |
| [stream-framing.md](stream-framing.md) | M2.7 — framing incremental / stream buffer |
| [byte-source.md](byte-source.md) | M2.8 — `ByteSource` + pipeline offline |
| [tcp-byte-source.md](tcp-byte-source.md) | M2.10 — `TcpByteSource` read-only (loopback tests) |
| [multi-capture-validation.md](multi-capture-validation.md) | M2.9 — estabilidad multi-captura (**DONE** / `VERIFIED_MULTI_CAPTURE`) |
| [message-inventory.md](message-inventory.md) | M3.1 — inventario de mensajes cross-capture |
| [payload-structure.md](payload-structure.md) | M3.2 — estructura observable de payloads |
| [message-correlation.md](message-correlation.md) | M3.3 — correlación / secuencias / transiciones |
| [state-machine.md](state-machine.md) | M3.4 — máquina de estados observacional |
| [protocol-spec-v0.1.md](protocol-spec-v0.1.md) | M4.1 — especificación BAP v0.1 |
| [unknown-registry.md](unknown-registry.md) | M4.1 — registro priorizado de UNKNOWN |
| [local-server.md](local-server.md) | M4.2 — servidor BAP local + replay (`SIMULATED_HANDSHAKE`) |
| [udp-evidence.md](udp-evidence.md) | M4.3 — evidencia UDP / transport discovery (read-only) |
| [message-codec.md](message-codec.md) | M4.4 — codec / registry / dispatcher BAP |
| [stateful-server.md](stateful-server.md) | M4.5 — servidor BAP local con estado explícito |
| [compatibility-client.md](compatibility-client.md) | M4.6 — cliente BAP de compatibilidad local |
| [external-client-boundary.md](external-client-boundary.md) | M4.7 — frontera de cliente externo (localhost) |
| [observation-harness.md](observation-harness.md) | M4.8 — harness de observación / diff seguro |
| [compatibility-matrix.md](compatibility-matrix.md) | M4.9 — matriz de compatibilidad de protocolo |
| [signon-analysis.md](signon-analysis.md) | M4.10 — análisis SignOn offline + session boundary |
| [encrypted-channel.md](encrypted-channel.md) | Canal AES-GCM |
| [keepalive.md](keepalive.md) | `0xFA` / `0xFB` |
| [nat.md](nat.md) | `0x12E` / `0x12F` |
| [activity-state.md](activity-state.md) | `0x12D` |
| [evidence-jsonl.md](evidence-jsonl.md) | Schema de `decrypted_bap.jsonl` (d1-re) |
| [capture-20260529-003132-notes.md](capture-20260529-003132-notes.md) | Validación M1 con captura real PS3 |
| [message-matrix.md](message-matrix.md) | Matriz consolidada |
| [unknowns.md](unknowns.md) | Preguntas abiertas |

## Fuentes

Fuente principal:

```text
kallsyms/d1-re
```

En especial:

- `README.md`
- `tools/ps3_decrypt_capture.py`
- capturas PS3 bajo `captures/` (estructura y metadatos; **no** se copian PCAPs, tokens ni secretos a este repositorio)

Ver también [external/README.md](../../external/README.md).

## Fuera de alcance (esta carpeta / Milestone 1)

- servidor TCP/UDP
- login server
- crypto runnable en `network/`
- matchmaking / gameplay
- launcher / cliente / base de datos
- copiar código de `d1-re` (licencia no declarada)
