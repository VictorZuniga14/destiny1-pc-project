# Message Inventory (M3.1)

Offline inventory of decrypted BAP messages across verified captures.

## Objetivo

Responder, con evidencia reproducible:

> ¿Qué message IDs aparecen, en qué dirección/contexto, con qué longitudes, y qué es estable o divergente entre capturas?

**No** afirma la semántica completa de los payloads.

## Fuentes

| Captura | Fixture (gitignored) |
| ------- | -------------------- |
| `20260529-003132` | `evidence/local/bap_session_verify.json` |
| `20260608-231100` | `evidence/local/bap_session_verify_20260608-231100.json` |

Consumo vía `BapOfflinePipeline` → `DecodedBapFrame`. Sin re-parsear framing ni reimplementar GCM.

Nombres de `docs/networking/message-matrix.md` / `messages.rs` se etiquetan **EXTERNAL_REFERENCE**, separados de **OBSERVED**.

## Modelo

```text
MessageObservation
  capture_id, frame_index, direction, frame_kind,
  message_id, context, payload_len, payload_sha256,
  (payload bytes in-memory only)

MessageInventory → groups by message_id
CaptureMessageInventory → per-capture summaries + startup_sequence
CrossCaptureMessageComparison → presence / dir / context / length status
```

## Fingerprinting

`payload_sha256` = SHA-256 hex del payload post-framing/crypto.  
Export versionado: **sin** `payload_hex` ni keys.

## Byte diff

`MessagePayloadDiff`: lengths, common prefix, first difference offset, different byte count.  
Sin interpretar campos (no `player_id`, etc.).

## Clasificación

| Label | Uso |
| ----- | --- |
| OBSERVED | Hecho de bytes/metadata |
| CROSS_CAPTURE_STABLE | Misma propiedad en ambas capturas |
| DIVERGENT | Diferencia observada |
| UNKNOWN | Sin evidencia |
| EXTERNAL_REFERENCE | Nombre externo (d1-re / matrix) |

## CLI

```bash
cargo run -- message-inventory fixtures/multi_capture/manifest.json
```

Escribe `fixtures/message_inventory/cross_capture_safe.json` (metadata + hashes counts; sin secretos).

## Limitaciones

- No schemas de payload.
- No prueba request/response semántica (solo `OBSERVED_SEQUENCE_PAIR` en ventanas de startup).
- Segunda sesión BAP de `20260608-231100` no incluida en el fixture actual.
- Keepalive timing sigue UNKNOWN.

## Related

- [multi-capture-validation.md](multi-capture-validation.md)
- [message-matrix.md](message-matrix.md)
