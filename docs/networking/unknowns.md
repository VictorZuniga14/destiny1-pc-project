# Unknowns

Lista explícita de preguntas abiertas. Nada de esto debe tratarse como resuelto en Milestone 1.

## Plataforma

- ¿El framing BAP es idéntico en PS4?
- ¿Es idéntico en Xbox?
- ¿Qué diferencias existen entre plataformas?
- ¿Los mismos `msg_id` y nombres aplican fuera de PS3?

**Estado:** UNKNOWN (evidencia directa actual = PS3 en `kallsyms/d1-re`).

## Networking

- ¿Qué tráfico utiliza UDP?
- ¿Cómo funciona realmente el gameplay networking?
- ¿Qué papel tienen los physics hosts?
- ¿Qué papel tienen los activity/world servers?
- ¿Cómo funciona NAT traversal a bajo nivel?
- ¿`0x12E`/`0x12F` solo reportan estado NAT sobre BAP/TCP, o disparan otro canal?

**Estado:** UNKNOWN.

**No asumir:** UDP como núcleo de `destiny1-network`.

## Protocol

- ¿Cuál es el schema de cada payload (`0x1E`, `0x1F`, `0x19`, `0x1A`, `0x79`, `0x7A`, `0xFA`, `0xFB`, `0x12D`, `0x12E`, `0x12F`, …)?
- ¿Qué significa exactamente `context` (u32 en clear/encrypted body)?
- ¿Qué campos contiene `session-login-request` más allá de existir como `0x19`?
- ¿Qué mensajes aparecen después del login, en qué orden, y con qué dependencias?
- ¿Hay kinds BAP distintos de `1` y `2`?
- ¿Hay rekey / renego del canal AES-GCM?
- ¿Cuál es el schema exacto on-disk de JSONL de terceros (p. ej. `decrypted_bap.jsonl` de `d1-re`)?
- ¿Qué AAD (si alguno) usa el wire real de Destiny? (el decryptor público de referencia pasa AAD vacío/`None`; no elevado a hecho de producto aquí)

**Estado:** mayormente UNKNOWN; crypto path de sesión CONFIRMED solo según el decryptor PS3.

### Primitive AES-GCM offline (Milestone 1.7)

`network/src/crypto/aead.rs` aporta AES-128-GCM genérico para fixtures sintéticos.

Eso **no** confirma por sí solo:

- reglas de nonce cliente/servidor en producción;
- AAD real del protocolo;
- derivación de session key desde SignOn/`0x1A`.

Esas piezas siguen en [encrypted-channel.md](encrypted-channel.md) / [session.md](session.md) con sus niveles de confianza previos.

### Evidencia JSONL (Milestones 1.5 / 1.8)

Schema del JSONL **propio del proyecto**: ver `network/src/jsonl.rs` / `network/README.md`.

Schema del JSONL **externo** `decrypted_bap.jsonl` (`kallsyms/d1-re`):

→ documentado en [evidence-jsonl.md](evidence-jsonl.md) (campos CONFIRMED desde el decryptor).

Adaptador local: `network/src/evidence_adapter.rs` (fixtures sintéticos del schema externo; sin capturas reales en el repo).

Compatibilidad con archivos reales locales (gitignored):

```text
CONFIRMED para captura PS3 20260529-003132
```

Ver [capture-20260529-003132-notes.md](capture-20260529-003132-notes.md).  
Otras capturas / plataformas: **REQUIRES TEST**.

### IDs observados sin nombre (captura 20260529-003132)

Vistos en timeline real; **sin semántica asignada**:

| ID | Notas |
| -- | ----- |
| `0x7B` | Frecuente en esa captura |
| `0x20` / `0x21` | Par request/response-like (solo por co-ocurrencia; no nombrado) |
| `0x15` / `0x16` | Idem |
| `0x17` / `0x18` | Idem |
| `0x12` / `0x13` | Idem |
| `0xAB` | Observado |

Estado: **UNKNOWN** (existencia CONFIRMED en esa captura; significado UNKNOWN).

### Keepalive interval (captura 20260529-003132)

**PROBABLE ~5 s** entre pares `0xFA`/`0xFB` en esa captura PS3 (también gaps ~6–13 s).  
No es regla general del protocolo.

## Client

- ¿Cómo se relaciona este protocolo con el cliente (orden de pantallas, Orbit, character select)?
- ¿Qué necesita el cliente antes de entrar en Orbit?
- ¿Qué fallos de red bloquean el progreso del cliente?

**Estado:** UNKNOWN a nivel de mapeo cliente↔wire en este repo.

## Legal / reutilización

- `kallsyms/d1-re` no declara licencia pública clara → no copiar código al proyecto.
- No commitear PCAPs, tokens, claves ni bodies de capturas.

## REQUIRES TEST (post analizador offline)

El analizador offline existe en `network/` y fue validado contra evidencia real local (gitignored) de la captura `20260529-003132`.

Follow-ups documentales / M2 (sin servidor):

- preservar `frame_kind` wire en timeline;
- timestamps relativos;
- reconstrucción de sesión / nonce / AAD sobre evidencia existente;
- inventariar payloads e IDs unknown sin inventar semántica.

No avanzar a un servidor TCP hasta completar reconstrucción de sesión offline con evidencia.
